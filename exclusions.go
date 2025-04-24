package main

import (
	"sync"
	"time"

	"github.com/jnesss/bpfview/types"
)

// ExclusionConfig holds all exclusion patterns
type ExclusionConfig struct {
	CommNames    []string
	ExePaths     []string
	UserNames    []string
	ContainerIDs []string
}

// ExclusionState tracks process tree state for exclusions
type ExclusionState struct {
	excludedPIDs map[uint32]struct{} // PIDs that matched exclusion rules
	includedPIDs map[uint32]struct{} // PIDs explicitly included due to tree tracking
	mu           sync.RWMutex
}

func NewExclusionState() *ExclusionState {
	return &ExclusionState{
		excludedPIDs: make(map[uint32]struct{}),
		includedPIDs: make(map[uint32]struct{}),
	}
}

// ExclusionEngine handles fast-path exclusion of high-volume processes
type ExclusionEngine struct {
	config ExclusionConfig
	mu     sync.RWMutex

	// Pattern matchers
	commMatcher      *PatternMatcher
	exePathMatcher   *PatternMatcher
	userMatcher      *PatternMatcher
	containerMatcher *PatternMatcher

	// Tree tracking
	state        *ExclusionState
	treeTracking bool
}

func NewExclusionEngine(config ExclusionConfig, enableTreeTracking bool) *ExclusionEngine {
	e := &ExclusionEngine{
		config:       config,
		treeTracking: enableTreeTracking,
		state:        NewExclusionState(),
	}

	// Initialize pattern matchers
	e.commMatcher = NewPatternMatcher(config.CommNames)
	e.exePathMatcher = NewPatternMatcher(config.ExePaths)
	e.userMatcher = NewPatternMatcher(config.UserNames)
	e.containerMatcher = NewPatternMatcher(config.ContainerIDs)

	return e
}

// ShouldExclude performs pattern-aware exclusion check with metrics
func (e *ExclusionEngine) ShouldExclude(info *types.ProcessInfo) bool {
	start := time.Now()
	defer func() {
		exclusionLatency.WithLabelValues("process").Observe(time.Since(start).Seconds())
	}()

	// Check tree tracking first
	if e.treeTracking {
		e.state.mu.RLock()
		// If parent is included, include this process
		if _, included := e.state.includedPIDs[info.PPID]; included {
			e.state.includedPIDs[info.PID] = struct{}{}
			e.state.mu.RUnlock()
			return false
		}
		// If parent is excluded, exclude this process
		if _, excluded := e.state.excludedPIDs[info.PPID]; excluded {
			e.state.excludedPIDs[info.PID] = struct{}{}
			e.state.mu.RUnlock()
			return true
		}
		e.state.mu.RUnlock()
	}

	excluded := false

	// Check comm name (usually fastest)
	if e.commMatcher.Matches(info.Comm) {
		excludedEventsTotal.WithLabelValues("process", "comm", info.Comm).Inc()
		excluded = true
	}

	if !excluded && info.ExePath != "" {
		// Check executable path
		if e.exePathMatcher.Matches(info.ExePath) {
			excludedEventsTotal.WithLabelValues("process", "exe_path", info.ExePath).Inc()
			excluded = true
		}
	}

	if !excluded && info.Username != "" {
		// Check executable path
		if e.userMatcher.Matches(info.Username) {
			excludedEventsTotal.WithLabelValues("process", "username", info.Username).Inc()
			excluded = true
		}
	}

	if !excluded && info.ContainerID != "" {
		// Check executable path
		if e.containerMatcher.Matches(info.ContainerID) {
			excludedEventsTotal.WithLabelValues("process", "container", info.ContainerID).Inc()
			excluded = true
		}
	}

	if excluded {
		// Track exclusion in tree state if needed
		if e.treeTracking {
			e.state.mu.Lock()
			e.state.excludedPIDs[info.PID] = struct{}{}
			e.state.mu.Unlock()
		}

		// Increment overall statistics
		size := len(info.Comm) + len(info.ExePath) + len(info.Username) +
			len(info.ContainerID) + 64 // Base struct size
		excludedEventSize.WithLabelValues("process").Observe(float64(size))
		exclusionMatchRate.WithLabelValues("process").Observe(1.0)
	}

	return excluded
}

// HandleProcessExit cleans up tree tracking state
func (e *ExclusionEngine) HandleProcessExit(pid uint32) {
	if !e.treeTracking {
		return
	}

	e.state.mu.Lock()
	defer e.state.mu.Unlock()

	delete(e.state.excludedPIDs, pid)
	delete(e.state.includedPIDs, pid)
}

// MarkProcessIncluded explicitly includes a process and its children
func (e *ExclusionEngine) MarkProcessIncluded(pid uint32) {
	if !e.treeTracking {
		return
	}

	e.state.mu.Lock()
	defer e.state.mu.Unlock()

	e.state.includedPIDs[pid] = struct{}{}
	delete(e.state.excludedPIDs, pid) // Remove from excluded if present
}

// UpdateConfig allows dynamic updates of exclusion patterns with pattern matching
func (e *ExclusionEngine) UpdateConfig(config ExclusionConfig) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.config = config

	// Rebuild pattern matchers
	e.commMatcher = NewPatternMatcher(config.CommNames)
	e.exePathMatcher = NewPatternMatcher(config.ExePaths)
	e.userMatcher = NewPatternMatcher(config.UserNames)
	e.containerMatcher = NewPatternMatcher(config.ContainerIDs)
}

func (e *ExclusionEngine) reportMetrics() {
	// Update pattern counts
	exclusionPatternCount.WithLabelValues("comm").Set(float64(len(e.config.CommNames)))
	exclusionPatternCount.WithLabelValues("exe_path").Set(float64(len(e.config.ExePaths)))
	exclusionPatternCount.WithLabelValues("username").Set(float64(len(e.config.UserNames)))
	exclusionPatternCount.WithLabelValues("container").Set(float64(len(e.config.ContainerIDs)))

	// For now we don't have a pattern matching cache
	// Future: Add caching if needed for performance
}

func (e *ExclusionEngine) recordExcludedEventSize(eventType string, size int) {
	excludedEventSize.WithLabelValues(eventType).Observe(float64(size))
}
