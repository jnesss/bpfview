// metrics.go
package main

import (
	"context"
	"runtime"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

// Event processing metrics track the lifecycle of events through the system
var (
	eventProcessingDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "bpfview_event_processing_duration_seconds",
			Help:    "Time spent processing events after initialization and cache operations",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 10),
		},
		[]string{"event_type"},
	)

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

	operationResults = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "bpfview_operation_results",
			Help: "Operation success and failure counts by event type and operation",
		},
		[]string{"event_type", "operation", "result"},
	)

	cacheMisses = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "bpfview_cache_misses_total",
			Help: "Number of cache misses by event type",
		},
		[]string{"event_type"},
	)
)

// Cache performance metrics track the process cache efficiency
var (
	cacheLookupDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "bpfview_cache_lookup_duration_seconds",
			Help:    "Time spent waiting for process info cache entries including retries",
			Buckets: prometheus.ExponentialBuckets(0.000001, 2, 12),
		},
		[]string{"event_type", "result"},
	)

	cacheWaitAttempts = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "bpfview_cache_wait_attempts",
			Help:    "Number of attempts before cache entry was found or gave up",
			Buckets: []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
		},
		[]string{"event_type", "result"},
	)

	cacheStats = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "bpfview_cache_stats",
			Help: "Cache performance statistics including size, hit ratio, memory usage",
		},
		[]string{"type"}, // size, hit_ratio, evictions, keys_added, cost_added, cost_evicted
	)
)

// System interaction metrics track resource usage
var (
	procReadsTotal = promauto.NewCounter(
		prometheus.CounterOpts{
			Name: "bpfview_proc_reads_total",
			Help: "Total number of /proc filesystem reads",
		},
	)

	excludedEventsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "bpfview_excluded_events_total",
			Help: "Total number of events excluded by filters",
		},
		[]string{"filter_type"},
	)

	resourceUsage = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "bpfview_resource_usage",
			Help: "Current resource utilization stats",
		},
		[]string{"resource"}, // memory, goroutines, file_descriptors
	)
)

// MetricsCollector handles periodic collection of metrics
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
	cacheStats.WithLabelValues("hit_ratio").Set(metrics.Ratio() * 100)
	cacheStats.WithLabelValues("evictions").Set(float64(metrics.KeysEvicted()))
	cacheStats.WithLabelValues("keys_added").Set(float64(metrics.KeysAdded()))
	cacheStats.WithLabelValues("cost_added").Set(float64(metrics.CostAdded()))
	cacheStats.WithLabelValues("cost_evicted").Set(float64(metrics.CostEvicted()))
	cacheStats.WithLabelValues("max_size").Set(float64(mc.cache.MaxSize()))

	// Update resource usage
	stats := runtime.MemStats{}
	runtime.ReadMemStats(&stats)
	resourceUsage.WithLabelValues("memory_bytes").Set(float64(stats.Alloc))
	resourceUsage.WithLabelValues("goroutines").Set(float64(runtime.NumGoroutine()))
}

// Timer wraps prometheus timer for event duration tracking
type Timer struct {
	timer *prometheus.Timer
}

func NewEventTimer(eventType string) *Timer {
	return &Timer{
		timer: prometheus.NewTimer(eventProcessingDuration.WithLabelValues(eventType)),
	}
}

func (t *Timer) ObserveDuration() {
	if t.timer != nil {
		t.timer.ObserveDuration()
	}
}

// TimerPair tracks both wait and processing time for an event
type TimerPair struct {
	waitTimer    *prometheus.Timer
	processTimer *prometheus.Timer
	eventType    string
	waitAttempts int
}

func NewTimerPair(eventType string) *TimerPair {
	return &TimerPair{
		waitTimer: prometheus.NewTimer(cacheLookupDuration.WithLabelValues(eventType, "pending")),
		eventType: eventType,
	}
}

func (tp *TimerPair) StartProcessing(cacheHit bool) {
	if tp.waitTimer != nil {
		tp.waitTimer.ObserveDuration()
	}
	result := "hit"
	if !cacheHit {
		result = "miss"
		cacheMisses.WithLabelValues(tp.eventType).Inc()
	}

	cacheWaitAttempts.WithLabelValues(tp.eventType, result).Observe(float64(tp.waitAttempts))
	tp.processTimer = prometheus.NewTimer(eventProcessingDuration.WithLabelValues(tp.eventType))
}

func (tp *TimerPair) IncrementAttempts() {
	tp.waitAttempts++
}

func (tp *TimerPair) ObserveDuration() {
	if tp.processTimer != nil {
		tp.processTimer.ObserveDuration()
	}
}
