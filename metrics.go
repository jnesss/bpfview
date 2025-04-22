// metrics.go
package main

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	// Event processing metrics
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

	eventProcessingDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "bpfview_event_processing_duration_seconds",
			Help:    "Time spent processing events after cache lookup",
			Buckets: prometheus.ExponentialBuckets(0.0001, 2, 10), // 100μs to 10s
		},
		[]string{"event_type"},
	)

	cacheLookupDuration = promauto.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "bpfview_cache_lookup_duration_seconds",
			Help:    "Time spent waiting for process cache entry",
			Buckets: prometheus.ExponentialBuckets(0.000001, 2, 12), // 1μs to 10s
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

	// Cache metrics
	cacheMetrics = promauto.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "bpfview_cache_metrics",
			Help: "Process cache performance metrics",
		},
		[]string{"metric"},
	)

	// System interaction metrics
	procReadsTotal = promauto.NewCounter(prometheus.CounterOpts{
		Name: "bpfview_proc_reads_total",
		Help: "Total number of /proc filesystem reads",
	})

	// Filter metrics
	excludedEventsTotal = promauto.NewCounterVec(
		prometheus.CounterOpts{
			Name: "bpfview_excluded_events_total",
			Help: "Total number of events excluded by filters",
		},
		[]string{"filter_type"},
	)
)

// MetricsCollector handles periodic collection of metrics
type MetricsCollector struct {
	cache *ProcessCache
	ctx   context.Context
	stop  context.CancelFunc
}

// NewMetricsCollector creates a new metrics collector
func NewMetricsCollector(cache *ProcessCache) *MetricsCollector {
	ctx, stop := context.WithCancel(context.Background())
	return &MetricsCollector{
		cache: cache,
		ctx:   ctx,
		stop:  stop,
	}
}

// Start begins periodic metrics collection
func (mc *MetricsCollector) Start() {
	go mc.collect()
}

// Stop halts metrics collection
func (mc *MetricsCollector) Stop() {
	mc.stop()
}

// collect periodically updates metrics
func (mc *MetricsCollector) collect() {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-mc.ctx.Done():
			return
		case <-ticker.C:
			mc.updateCacheMetrics()
		}
	}
}

// updateCacheMetrics collects and updates cache-related metrics
func (mc *MetricsCollector) updateCacheMetrics() {
	if mc.cache == nil {
		return
	}

	metrics := mc.cache.GetMetrics()
	if metrics == nil {
		return
	}

	cacheMetrics.WithLabelValues("size").Set(float64(metrics.KeysAdded() - metrics.KeysEvicted()))
	cacheMetrics.WithLabelValues("hits").Set(float64(metrics.Hits()))
	cacheMetrics.WithLabelValues("misses").Set(float64(metrics.Misses()))
	cacheMetrics.WithLabelValues("hit_ratio").Set(metrics.Ratio() * 100)
	cacheMetrics.WithLabelValues("cost_added").Set(float64(metrics.CostAdded()))
	cacheMetrics.WithLabelValues("evictions").Set(float64(metrics.KeysEvicted()))
}

// Timer wraps a prometheus timer for event duration tracking
type Timer struct {
	timer *prometheus.Timer
}

// NewEventTimer creates a new timer for tracking event processing duration
func NewEventTimer(eventType string) *Timer {
	return &Timer{
		timer: prometheus.NewTimer(eventProcessingDuration.WithLabelValues(eventType)),
	}
}

// ObserveDuration records the duration since the timer was created
func (t *Timer) ObserveDuration() {
	t.timer.ObserveDuration()
}

// TimerPair tracks both wait and processing time
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
	// Record wait time with appropriate result label
	tp.waitTimer.ObserveDuration()
	result := "hit"
	if !cacheHit {
		result = "miss"
	}

	// Record number of attempts
	cacheWaitAttempts.WithLabelValues(tp.eventType, result).Observe(float64(tp.waitAttempts))

	// Start processing timer
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
