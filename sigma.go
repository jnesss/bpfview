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
	"time"

	"github.com/bradleyjkemp/sigma-go"
	"github.com/bradleyjkemp/sigma-go/evaluator"
	"github.com/fsnotify/fsnotify"
)

type DetectionEvent struct {
	EventType  string
	Data       map[string]interface{}
	Timestamp  time.Time
	ProcessUID string // Just store process identifier
	PID        uint32 // Keep PID for potential cache lookup
}

type SigmaEngine struct {
	rulesDir   string
	evaluators map[string]*evaluator.RuleEvaluator
	watcher    *fsnotify.Watcher
	mu         sync.RWMutex

	eventChan chan DetectionEvent
	queueSize int
	dropCount atomic.Int64 // Track dropped events
}

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

	engine := &SigmaEngine{
		rulesDir:   rulesDir,
		evaluators: make(map[string]*evaluator.RuleEvaluator),
		watcher:    watcher,
		eventChan:  make(chan DetectionEvent, queueSize),
		queueSize:  queueSize,
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

	return engine, nil
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
		"rules_loaded":   int64(len(se.evaluators)),
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

	// Only process applicable process creation rules
	if !isProcessCreationRule(rule) {
		log.Printf("Ignoring non-process-creation rule: %s from %s", rule.Title, path)
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
	se.evaluators[rule.ID] = ruleEvaluator
	se.mu.Unlock()

	log.Printf("Loaded process creation rule: %s (%s)", rule.Title, path)
	return nil
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

func createFieldMappings() sigma.Config {
	return sigma.Config{
		Title: "BPFView Process Creation Mappings",
		FieldMappings: map[string]sigma.FieldMapping{
			"CommandLine":       {TargetNames: []string{"CommandLine"}},
			"ParentCommandLine": {TargetNames: []string{"ParentCommandLine"}},
			"Image":             {TargetNames: []string{"Image"}},
			"ParentImage":       {TargetNames: []string{"ParentImage"}},
			"User":              {TargetNames: []string{"Username"}},
			"ProcessId":         {TargetNames: []string{"ProcessId"}},
			"ParentProcessId":   {TargetNames: []string{"ParentProcessId"}},
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
				// Remove rule from evaluators if it exists
				se.mu.Lock()
				delete(se.evaluators, event.Name)
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

func (se *SigmaEngine) Close() error {
	if se.watcher != nil {
		return se.watcher.Close()
	}
	return nil
}
