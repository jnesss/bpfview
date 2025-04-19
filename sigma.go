// sigma.go
package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/bradleyjkemp/sigma-go"
	"github.com/bradleyjkemp/sigma-go/evaluator"
	"github.com/fsnotify/fsnotify"

	"github.com/jnesss/bpfview/types"
)

type DetectionEvent struct {
	EventType       string
	Data            map[string]interface{}
	Timestamp       time.Time
	ProcessUID      string // Just store process identifier
	PID             uint32 // Keep PID for potential cache lookup
	DetectionSource string
}

type SigmaEngine struct {
	rulesDir     string
	processRules map[string]*evaluator.RuleEvaluator
	networkRules map[string]*evaluator.RuleEvaluator
	watcher      *fsnotify.Watcher
	mu           sync.RWMutex

	eventChan chan DetectionEvent
	queueSize int
	dropCount atomic.Int64 // Track dropped events
	running   atomic.Bool  // Track if processing worker is running
}

var memoryDumper *MemoryDumper

func NewSigmaEngine(rulesDir string, queueSize int) (*SigmaEngine, error) {
	if queueSize <= 0 {
		queueSize = 10000 // Default size if not specified
	}

	// Verify rules directory exists
	if _, err := os.Stat(rulesDir); os.IsNotExist(err) {
		return nil, fmt.Errorf(`sigma rules directory "%s" does not exist. 
Either:
1. Create a 'rules' subdirectory in your current directory and add .yml rules files
2. Use --sigma-rules to specify your rules directory location`, rulesDir)
	}

	// Create watcher
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return nil, fmt.Errorf("failed to create file watcher: %v", err)
	}

	// Initialize memory dumper
	dumper, err := NewMemoryDumper("./dumps")
	if err != nil {
		return nil, fmt.Errorf("failed to initialize memory dumper: %v", err)
	}
	memoryDumper = dumper

	engine := &SigmaEngine{
		rulesDir:     rulesDir,
		processRules: make(map[string]*evaluator.RuleEvaluator),
		networkRules: make(map[string]*evaluator.RuleEvaluator),
		watcher:      watcher,
		eventChan:    make(chan DetectionEvent, queueSize),
		queueSize:    queueSize,
	}

	// Initial rule loading
	if err := engine.loadAllRules(); err != nil {
		watcher.Close()
		return nil, fmt.Errorf("failed to load rules: %v", err)
	}

	// Setup recursive directory watching
	if err := engine.setupWatcher(); err != nil {
		watcher.Close()
		return nil, fmt.Errorf("failed to setup watcher: %v", err)
	}

	// Start processing worker
	if err := engine.Start(); err != nil {
		watcher.Close()
		return nil, fmt.Errorf("failed to start processing: %v", err)
	}

	return engine, nil
}

// Add worker control methods
func (se *SigmaEngine) Start() error {
	if se.running.Load() {
		return fmt.Errorf("sigma engine already running")
	}

	se.running.Store(true)
	go se.processEvents()

	log.Printf("Started Sigma rule processing")
	return nil
}

// Add event processing loop
func (se *SigmaEngine) processEvents() {
	for se.running.Load() {
		select {
		case evt := <-se.eventChan:
			se.handleEvent(evt)
		default:
			// No events waiting - sleep briefly
			time.Sleep(10 * time.Millisecond)
		}
	}
}

func (se *SigmaEngine) handleEvent(evt DetectionEvent) {
	se.mu.RLock()
	defer se.mu.RUnlock()

	globalLogger.Debug("sigma", "Processing detection event type: %s, source: %s",
		evt.EventType, evt.DetectionSource)

	var relevantRules map[string]*evaluator.RuleEvaluator
	switch evt.DetectionSource {
	case "process_creation":
		relevantRules = se.processRules
	case "network_connection", "dns_query":
		relevantRules = se.networkRules
	default:
		return
	}

	// Check each rule
	for _, evaluator := range relevantRules {
		result, err := evaluator.Matches(context.Background(), evt.Data)
		if err != nil {
			log.Printf("Error evaluating rule %s: %v", evaluator.Rule.ID, err)
			continue
		}

		if result.Match {

			globalLogger.Debug("sigma", "Rule matched: %s", evaluator.Rule.Title)
			globalLogger.Debug("sigma", "Event Data: %v", evt.Data)

			// Convert SearchResults
			matchDetails := getMatchDetails(evaluator.Rule, result.SearchResults)

			// Create SigmaMatch
			match := &types.SigmaMatch{
				Timestamp:  evt.Timestamp,
				RuleID:     evaluator.Rule.ID,
				RuleName:   evaluator.Rule.Title,
				RuleLevel:  evaluator.Rule.Level,
				ProcessUID: evt.ProcessUID,
				PID:        evt.PID,
				MatchedFields: map[string]interface{}{
					"details": matchDetails,
				},
				EventData:       evt.Data,
				RuleDescription: evaluator.Rule.Description,
				RuleReferences:  evaluator.Rule.References,
				RuleTags:        evaluator.Rule.Tags,
				DetectionSource: evt.DetectionSource,
			}

			// Try to get process info for matches
			//  we wont get it if handleEvent is post process Terminate and thats ok
			if info, exists := GetProcessFromCache(evt.PID); exists {
				match.ProcessInfo = info
				// Get parent info only if we have the process info
				if pinfo, exists := GetProcessFromCache(info.PPID); exists {
					match.ParentInfo = pinfo
				}
			}

			// Add network correlation if available
			if networkUID, ok := evt.Data["network_uid"].(string); ok {
				match.NetworkUID = networkUID
			}

			// Handle any response actions defined in the rule
			if actions, ok := evaluator.Rule.AdditionalFields["actions"].([]interface{}); ok {
				var flags uint32
				var needsTermination, needsMemoryDump bool
				match.ResponseActions = []string{}

				// Calculate all requested actions
				for _, action := range actions {
					if actionMap, ok := action.(map[string]interface{}); ok {
						if actionType, ok := actionMap["type"].(string); ok {
							// Record the action
							match.ResponseActions = append(match.ResponseActions, actionType)

							// Set appropriate flags for BPF-handled restrictions
							switch actionType {
							case types.ACTION_BLOCK_NETWORK:
								flags |= types.BLOCK_NETWORK
							case types.ACTION_PREVENT_CHILDREN:
								flags |= types.PREVENT_CHILDREN
							case types.ACTION_TERMINATE:
								needsTermination = true
							case types.ACTION_DUMP_MEMORY:
								needsMemoryDump = true
							}
						}
					}
				}

				// Apply BPF restrictions if any
				if flags != 0 {
					if err := responseManager.ApplyRestrictions(evt.PID, flags); err != nil {
						globalLogger.Error("sigma", "Failed to apply restrictions to PID %d: %v", evt.PID, err)
					}
				}

				// Handle memory dump if requested
				if needsMemoryDump {
					dumpPath, err := memoryDumper.DumpProcessMemory(evt.PID,
						fmt.Sprintf("Sigma rule match: %s", evaluator.Rule.Title))
					if err != nil {
						globalLogger.Error("sigma", "Failed to dump memory for PID %d: %v", evt.PID, err)
					} else {
						globalLogger.Info("sigma", "Memory dump saved to: %s", dumpPath)
					}
				}

				// Handle termination if requested
				if needsTermination {
					proc, err := os.FindProcess(int(evt.PID))
					if err != nil {
						globalLogger.Error("sigma", "Failed to find process PID %d: %v", evt.PID, err)
					} else {
						err = proc.Signal(syscall.SIGKILL)
						if err != nil {
							globalLogger.Error("sigma", "Failed to terminate PID %d: %v", evt.PID, err)
						} else {
							globalLogger.Info("sigma", "Successfully terminated PID %d due to rule match: %s", evt.PID, evaluator.Rule.Title)
						}
					}
				}
			}

			// Write match directly to logger
			if globalLogger != nil {
				if err := globalLogger.LogSigmaMatch(match); err != nil {
					log.Printf("Error formatting sigma match: %v", err)
				}
			}
		}
	}
}

func (se *SigmaEngine) Close() error {
	se.Stop()

	// Close channels
	close(se.eventChan)

	// Close watcher
	if se.watcher != nil {
		return se.watcher.Close()
	}
	return nil
}

func (se *SigmaEngine) Stop() {
	se.running.Store(false)
}

func (se *SigmaEngine) SubmitEvent(evt DetectionEvent) {
	select {
	case se.eventChan <- evt:
		// Event accepted
	default:
		// Channel full - increment drop counter
		se.dropCount.Add(1)
		if se.dropCount.Load()%1000 == 0 { // Log every 1000th drop
			log.Printf("WARNING: Dropped %d Sigma detection events due to full queue",
				se.dropCount.Load())
		}
	}
}

func (se *SigmaEngine) GetMetrics() map[string]int64 {
	return map[string]int64{
		"dropped_events": se.dropCount.Load(),
		"queue_size":     int64(se.queueSize),
		"process_rules":  int64(len(se.processRules)),
		"network_rules":  int64(len(se.networkRules)),
	}
}

func (se *SigmaEngine) loadAllRules() error {
	// Walk through all subdirectories
	return filepath.Walk(se.rulesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		// Skip directories
		if info.IsDir() {
			return nil
		}

		// Only process .yml and .yaml files
		if ext := filepath.Ext(path); ext != ".yml" && ext != ".yaml" {
			return nil
		}

		return se.loadRuleFile(path)
	})
}

func hasAnyField(detection sigma.Detection, fields []string) bool {
	// Check each search condition in the detection
	for _, search := range detection.Searches {
		// Check each matcher in the search
		for _, matchers := range search.EventMatchers {
			for _, matcher := range matchers {
				// Check if the field name is in our list
				for _, field := range fields {
					if matcher.Field == field {
						return true
					}
				}
			}
		}
	}
	return false
}

func (se *SigmaEngine) loadRuleFile(path string) error {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read rule file %s: %v", path, err)
	}

	// Check if this is actually a rule file
	fileType := sigma.InferFileType(content)
	if fileType != sigma.RuleFile {
		log.Printf("Ignoring non-rule file: %s", path)
		return nil
	}

	rule, err := sigma.ParseRule(content)
	if err != nil {
		return fmt.Errorf("failed to parse rule %s: %v", path, err)
	}

	if isNetworkRule(rule) {
		log.Printf("Loading network rule: %s (%s)", rule.Title, path)
	} else if isProcessCreationRule(rule) {
		log.Printf("Loading process creation rule: %s (%s)", rule.Title, path)
	} else {
		log.Printf("Ignoring rule: %s from %s", rule.Title, path)
		return nil
	}

	// Create config with our field mappings
	config := createFieldMappings()

	// Create evaluator
	ruleEvaluator := evaluator.ForRule(rule,
		evaluator.WithConfig(config),
		evaluator.WithPlaceholderExpander(func(ctx context.Context, name string) ([]string, error) {
			return nil, nil
		}),
	)

	// Store in evaluators map
	se.mu.Lock()
	if isNetworkRule(rule) {
		se.networkRules[rule.ID] = ruleEvaluator
	} else if isProcessCreationRule(rule) {
		se.processRules[rule.ID] = ruleEvaluator
	}
	se.mu.Unlock()

	return nil
}

func getMatchDetails(rule sigma.Rule, searchResults map[string]bool) string {
	var details strings.Builder

	// Look through each matched search condition
	for searchName, matched := range searchResults {
		if !matched {
			continue
		}

		// Find the corresponding search in the rule
		if search, ok := rule.Detection.Searches[searchName]; ok {
			// Handle field matchers
			if len(search.EventMatchers) > 0 {
				for i, matcher := range search.EventMatchers {
					if i > 0 {
						details.WriteString(" AND ")
					}

					for j, fieldMatch := range matcher {
						if j > 0 {
							details.WriteString(" WITH ")
						}

						op := "equals"
						if len(fieldMatch.Modifiers) > 0 {
							op = strings.Join(fieldMatch.Modifiers, " ")
						}
						details.WriteString(fmt.Sprintf("'%s' %s '%v'",
							fieldMatch.Field,
							op,
							fieldMatch.Values[0])) // Use first value for now
					}
				}
			}
		}
	}

	if details.Len() == 0 {
		if len(rule.Detection.Conditions) > 0 {
			if marshalledValue, err := rule.Detection.Conditions[0].MarshalYAML(); err == nil {
				return fmt.Sprintf("matched condition: %v", marshalledValue)
			}
		}
		return "matched"
	}

	return details.String()
}

func isProcessCreationRule(rule sigma.Rule) bool {
	// Check if explicitly marked as Windows-only
	if rule.Logsource.Product == "windows" {
		log.Printf("Ignoring Windows-specific rule: %s", rule.Title)
		return false
	}

	// Check for platform in AdditionalFields
	if platform, ok := rule.Logsource.AdditionalFields["platform"]; ok {
		if platformStr, ok := platform.(string); ok &&
			!strings.Contains(strings.ToLower(platformStr), "linux") {
			log.Printf("Ignoring non-Linux rule: %s (platform: %s)",
				rule.Title, platformStr)
			return false
		}
	}

	// Check for process creation category/service
	if rule.Logsource.Category == "process_creation" {
		return true
	}

	// Some rules might use service instead of category
	if rule.Logsource.Service == "process_creation" {
		return true
	}

	// Some rules don't specify category/service but are clearly process related
	if rule.Title != "" && (strings.Contains(strings.ToLower(rule.Title), "process") ||
		strings.Contains(strings.ToLower(rule.Description), "process")) {
		log.Printf("Loading ambiguous process rule: %s", rule.Title)
		return true
	}

	return false
}

func isNetworkRule(rule sigma.Rule) bool {
	if rule.Logsource.Product == "windows" {
		return false
	}

	// First, check explicitly for the category - this should be the primary criterion
	if rule.Logsource.Category == "network_connection" {
		return true
	}

	// If the rule explicitly defines a different category, respect that
	if rule.Logsource.Category == "process_creation" ||
		rule.Logsource.Category == "process_access" ||
		rule.Logsource.Category == "file_event" {
		return false
	}

	// Only use description-based heuristics for rules without a clear category
	if rule.Logsource.Category == "" && (strings.Contains(strings.ToLower(rule.Description), "network") ||
		strings.Contains(strings.ToLower(rule.Description), "connection") ||
		strings.Contains(strings.ToLower(rule.Description), "dns") ||
		hasAnyField(rule.Detection, []string{"DestinationHostname", "DestinationPort", "DestinationIp"})) {
		return true
	}

	return false
}

func createFieldMappings() sigma.Config {
	return sigma.Config{
		Title: "BPFView Process and Network Mappings",
		FieldMappings: map[string]sigma.FieldMapping{
			// Process fields
			"CommandLine":       {TargetNames: []string{"CmdLine"}},
			"ParentCommandLine": {TargetNames: []string{"ParentCmdLine"}},
			"Image":             {TargetNames: []string{"Image"}},
			"ParentImage":       {TargetNames: []string{"ParentImage"}},
			"User":              {TargetNames: []string{"User"}},
			"ProcessId":         {TargetNames: []string{"ProcessId"}},
			"ParentProcessId":   {TargetNames: []string{"ParentProcessId"}},
			"CurrentDirectory":  {TargetNames: []string{"CurrentDirectory"}},
			"ProcessName":       {TargetNames: []string{"ProcessName"}},

			// Network fields
			"DestinationPort":     {TargetNames: []string{"DestinationPort"}},
			"DestinationHostname": {TargetNames: []string{"DestinationHostname"}},
			"DestinationIp":       {TargetNames: []string{"DestinationIp"}},
			"Initiated":           {TargetNames: []string{"Initiated"}},
		},
	}
}

func (se *SigmaEngine) setupWatcher() error {
	// Walk through directories to watch them all
	err := filepath.Walk(se.rulesDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return se.watcher.Add(path)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("failed to setup recursive watching: %v", err)
	}

	// Start watching for changes
	go se.watchRules()

	return nil
}

func (se *SigmaEngine) watchRules() {
	for {
		select {
		case event, ok := <-se.watcher.Events:
			if !ok {
				return
			}

			// Skip non-yaml files
			ext := filepath.Ext(event.Name)
			if ext != ".yml" && ext != ".yaml" {
				continue
			}

			log.Printf("Rule file change detected: %s", event.Name)

			// Handle the change
			if event.Op&(fsnotify.Write|fsnotify.Create) != 0 {
				if err := se.loadRuleFile(event.Name); err != nil {
					log.Printf("Error loading modified rule %s: %v", event.Name, err)
				}
			} else if event.Op&fsnotify.Remove != 0 {
				// For removal, we need to check both maps
				se.mu.Lock()
				// Try to read the file one last time to determine its type
				if content, err := ioutil.ReadFile(event.Name); err == nil {
					if rule, err := sigma.ParseRule(content); err == nil {
						if isNetworkRule(rule) {
							delete(se.networkRules, rule.ID)
						} else if isProcessCreationRule(rule) {
							delete(se.processRules, rule.ID)
						}
					}
				} else {
					// If we can't read the file anymore, we need to check both maps
					// We'll use the filename as a fallback key
					delete(se.networkRules, event.Name)
					delete(se.processRules, event.Name)
				}
				se.mu.Unlock()
			}

		case err, ok := <-se.watcher.Errors:
			if !ok {
				return
			}
			log.Printf("Error watching rules directory: %v", err)
		}
	}
}
