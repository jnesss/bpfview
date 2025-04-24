// metrics.go
package main

import (
	"context"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Basic event counting
var (
	eventCounter = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "bpfview_events_total",
			Help: "Total number of events processed by type",
		},
		[]string{"event_type"},
	)

	eventProcessingErrors = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "bpfview_processing_errors_total",
			Help: "Total number of event processing errors by type",
		},
		[]string{"event_type"},
	)

	excludedEventsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "bpfview_excluded_events_total",
			Help: "Total number of events excluded by filters",
		},
		[]string{"filter_type"},
	)

	operationResults = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "bpfview_operation_results",
			Help: "Operation success and failure counts by event type and operation",
		},
		[]string{"event_type", "operation", "result"},
	)
)

// Proc reads counter
var (
	procReadsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "bpfview_proc_reads_total",
			Help: "Total number of /proc filesystem reads",
		},
	)

	processInfoProcReads = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "bpfview_process_info_proc_reads",
			Help: "Number of /proc reads by process info level",
		},
		[]string{"level", "file"}, // track which files we're reading at each level
	)
)

// Process info metrics
var (
	processInfoDurations = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "bpfview_process_info_duration_seconds",
			Help:    "Time spent collecting process information by level",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 10),
		},
		[]string{"level"}, // level will be "minimal", "basic", "full"
	)

	processInfoLevelStats = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "bpfview_process_info_level_total",
			Help: "Number of process info collections by level",
		},
		[]string{"level", "result"}, // level will be minimal/basic/full, result success/failure
	)
)

// Cache metrics
var (
	cacheMisses = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "bpfview_cache_misses_total",
			Help: "Number of cache misses by event type",
		},
		[]string{"event_type"},
	)

	cacheStats = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "bpfview_cache_stats",
			Help: "Cache performance statistics including size, hit ratio, memory usage",
		},
		[]string{"type"}, // size, hit_ratio, evictions, keys_added, cost_added, cost_evicted
	)
)

// System resource usage
var (
	resourceUsage = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "bpfview_resource_usage",
			Help: "Current resource utilization stats",
		},
		[]string{"resource"}, // memory, goroutines, file_descriptors
	)
)

// Phase timing metrics
var (
	// Overall handler timings
	handlerDurations = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "bpfview_handler_duration_seconds",
			Help:    "Duration of event handlers by name",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 12),
		},
		[]string{"handler"},
	)

	// Individual phase timings
	phaseDurations = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "bpfview_handler_phase_duration_seconds",
			Help:    "Duration of phases within event handlers",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 12),
		},
		[]string{"handler", "phase"},
	)

	// Percentage of handler time spent in each phase
	phasePercentages = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "bpfview_handler_phase_percentage",
			Help: "Percentage of handler time spent in each phase",
		},
		[]string{"handler", "phase"},
	)
)

// PhaseTimer tracks detailed timings within a handler
type PhaseTimer struct {
	handlerName  string
	phases       map[string]time.Duration
	phaseCounts  map[string]int
	currentPhase string
	phaseStart   time.Time
	totalTime    time.Duration
	startTime    time.Time
	count        int
	mu           sync.Mutex
}

// Global registry of phase timers
var (
	phaseTimersRegistry = make(map[string]*PhaseTimer)
	phaseTimersMutex    sync.RWMutex
)

// GetPhaseTimer returns a PhaseTimer for the specified handler
func GetPhaseTimer(handlerName string) *PhaseTimer {
	phaseTimersMutex.RLock()
	timer, exists := phaseTimersRegistry[handlerName]
	phaseTimersMutex.RUnlock()

	if !exists {
		timer = &PhaseTimer{
			handlerName: handlerName,
			phases:      make(map[string]time.Duration),
			phaseCounts: make(map[string]int),
		}

		phaseTimersMutex.Lock()
		phaseTimersRegistry[handlerName] = timer
		phaseTimersMutex.Unlock()
	}

	return timer
}

// StartTiming begins timing the entire handler
func (p *PhaseTimer) StartTiming() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.startTime = time.Now()
	p.count++
}

// StartPhase begins timing a specific phase
func (p *PhaseTimer) StartPhase(phase string) {
	p.mu.Lock()
	defer p.mu.Unlock()

	// End current phase if needed
	if p.currentPhase != "" {
		elapsed := time.Since(p.phaseStart)
		p.phases[p.currentPhase] += elapsed
		p.phaseCounts[p.currentPhase]++
	}

	p.currentPhase = phase
	p.phaseStart = time.Now()
}

// EndTiming completes timing and records metrics
func (p *PhaseTimer) EndTiming() {
	p.mu.Lock()
	defer p.mu.Unlock()

	// End current phase if any
	if p.currentPhase != "" {
		elapsed := time.Since(p.phaseStart)
		p.phases[p.currentPhase] += elapsed
		p.phaseCounts[p.currentPhase]++
		p.currentPhase = ""
	}

	handlerDuration := time.Since(p.startTime)
	p.totalTime += handlerDuration

	// Record handler duration metric
	handlerDurations.WithLabelValues(p.handlerName).Observe(
		handlerDuration.Seconds(),
	)

	// Record phase metrics
	for phase, duration := range p.phases {
		// Calculate average duration for this phase
		avgDuration := duration
		if p.phaseCounts[phase] > 0 {
			avgDuration = duration / time.Duration(p.phaseCounts[phase])
		}

		phaseDurations.WithLabelValues(p.handlerName, phase).Observe(
			avgDuration.Seconds(),
		)

		// Update percentage of total time spent in this phase
		if p.totalTime > 0 {
			percentage := float64(duration) / float64(p.totalTime) * 100
			phasePercentages.WithLabelValues(p.handlerName, phase).Set(percentage)
		}
	}
}

// ResetTimings clears accumulated timing data
func (p *PhaseTimer) ResetTimings() {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.phases = make(map[string]time.Duration)
	p.phaseCounts = make(map[string]int)
	p.totalTime = 0
	p.count = 0
}

// GetPhaseBreakdown returns phase timing details for reporting
type PhaseStats struct {
	Duration   time.Duration
	Count      int
	AvgTime    time.Duration
	Percentage float64
}

func (p *PhaseTimer) GetPhaseBreakdown() map[string]PhaseStats {
	p.mu.Lock()
	defer p.mu.Unlock()

	result := make(map[string]PhaseStats)

	for phase, duration := range p.phases {
		count := p.phaseCounts[phase]
		avgTime := duration
		if count > 0 {
			avgTime = duration / time.Duration(count)
		}

		percentage := 0.0
		if p.totalTime > 0 {
			percentage = float64(duration) / float64(p.totalTime) * 100
		}

		result[phase] = PhaseStats{
			Duration:   duration,
			Count:      count,
			AvgTime:    avgTime,
			Percentage: percentage,
		}
	}

	return result
}

// GetSortedPhases returns phases sorted by percentage (descending)
func (p *PhaseTimer) GetSortedPhases() []string {
	p.mu.Lock()
	defer p.mu.Unlock()

	phases := make([]string, 0, len(p.phases))
	for phase := range p.phases {
		phases = append(phases, phase)
	}

	// Calculate percentages for sorting
	percentages := make(map[string]float64)
	for phase, duration := range p.phases {
		if p.totalTime > 0 {
			percentages[phase] = float64(duration) / float64(p.totalTime) * 100
		} else {
			percentages[phase] = 0
		}
	}

	// Sort by percentage (descending)
	sort.Slice(phases, func(i, j int) bool {
		return percentages[phases[i]] > percentages[phases[j]]
	})

	return phases
}

// GetStatistics returns overall statistics for this handler
func (p *PhaseTimer) GetStatistics() (count int, totalTime time.Duration, avgTime time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.count > 0 {
		return p.count, p.totalTime, p.totalTime / time.Duration(p.count)
	}
	return p.count, p.totalTime, 0
}

// PrintHandlerBreakdown prints a tree-style breakdown of handler timing
func PrintHandlerBreakdown(handler string) string {
	phaseTimersMutex.RLock()
	timer, exists := phaseTimersRegistry[handler]
	phaseTimersMutex.RUnlock()

	if !exists || timer == nil {
		return "No data available for handler: " + handler
	}

	count, _, avgTime := timer.GetStatistics()
	sortedPhases := timer.GetSortedPhases()
	breakdown := timer.GetPhaseBreakdown()

	var result strings.Builder

	result.WriteString(fmt.Sprintf("\n%s Handler Timing Breakdown\n", strings.Title(handler)))
	result.WriteString("=====================================\n")
	result.WriteString(fmt.Sprintf("%s: avg=%.3fms (count=%d)\n",
		handler, float64(avgTime)/float64(time.Millisecond), count))

	for i, phase := range sortedPhases {
		stats := breakdown[phase]

		// Use different characters for last item
		prefix := "  ├─ "
		if i == len(sortedPhases)-1 {
			prefix = "  └─ "
		}

		result.WriteString(fmt.Sprintf("%s%s: avg=%.3fms (%.1f%%)\n",
			prefix,
			phase,
			float64(stats.AvgTime)/float64(time.Millisecond),
			stats.Percentage,
		))
	}

	return result.String()
}

// ListRegisteredHandlers returns all registered handlers
func ListRegisteredHandlers() []string {
	phaseTimersMutex.RLock()
	defer phaseTimersMutex.RUnlock()

	handlers := make([]string, 0, len(phaseTimersRegistry))
	for handler := range phaseTimersRegistry {
		handlers = append(handlers, handler)
	}

	sort.Strings(handlers)
	return handlers
}

// MetricsCollector handles periodic collection of system metrics
type MetricsCollector struct {
	cache *ProcessCache
	ctx   context.Context
	stop  context.CancelFunc
}

func NewMetricsCollector(cache *ProcessCache) *MetricsCollector {
	ctx, stop := context.WithCancel(context.Background())
	return &MetricsCollector{
		cache: cache,
		ctx:   ctx,
		stop:  stop,
	}
}

func (mc *MetricsCollector) Start() {
	go mc.collect()
}

func (mc *MetricsCollector) Stop() {
	mc.stop()
}

func (mc *MetricsCollector) collect() {
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-mc.ctx.Done():
			return
		case <-ticker.C:
			mc.updateMetrics()
		}
	}
}

func (mc *MetricsCollector) updateMetrics() {
	if mc.cache == nil {
		return
	}

	metrics := mc.cache.GetMetrics()
	if metrics == nil {
		return
	}

	// Update cache stats
	cacheStats.WithLabelValues("size").Set(float64(metrics.KeysAdded() - metrics.KeysEvicted()))
	cacheStats.WithLabelValues("max_size").Set(float64(mc.cache.MaxSize()))
	cacheStats.WithLabelValues("hit_ratio").Set(metrics.Ratio() * 100)
	cacheStats.WithLabelValues("evictions").Set(float64(metrics.KeysEvicted()))
	cacheStats.WithLabelValues("keys_added").Set(float64(metrics.KeysAdded()))
	cacheStats.WithLabelValues("cost_added").Set(float64(metrics.CostAdded()))
	cacheStats.WithLabelValues("cost_evicted").Set(float64(metrics.CostEvicted()))

	// Update resource usage
	stats := runtime.MemStats{}
	runtime.ReadMemStats(&stats)
	resourceUsage.WithLabelValues("memory_bytes").Set(float64(stats.Alloc))
	resourceUsage.WithLabelValues("goroutines").Set(float64(runtime.NumGoroutine()))
}
