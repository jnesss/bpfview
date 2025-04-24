package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"text/tabwriter"
	"os"
)

type MetricSample struct {
	Name   string
	Labels map[string]string
	Value  float64
}

type ExclusionStats struct {
	Total          float64
	ByType         map[string]map[string]float64 // rule_type -> pattern -> count
	LatencyAvg     float64
	LatencyMax     float64
	PatternCount   map[string]float64
	ExcludedEvents map[string]float64
}

func main() {
	metricsURL := flag.String("url", "http://localhost:2112/metrics", "URL to fetch Prometheus metrics from")
	handler := flag.String("handler", "", "Handler to analyze (process_exec, process_fork, process_exit, dns_event, network_event, tls_event)")
	listHandlers := flag.Bool("list", false, "List all available handlers")
	all := flag.Bool("all", false, "Show stats for all handlers")
	showExclusions := flag.Bool("exclusions", false, "Show detailed exclusion statistics")
	refreshInterval := flag.Int("refresh", 0, "Refresh interval in seconds (0 for one-time)")
	flag.Parse()

	if *refreshInterval > 0 {
		for {
			clearScreen()
			analyzeMetrics(*metricsURL, *handler, *listHandlers, *all, *showExclusions)
			time.Sleep(time.Duration(*refreshInterval) * time.Second)
		}
	} else {
		analyzeMetrics(*metricsURL, *handler, *listHandlers, *all, *showExclusions)
	}
}

func analyzeMetrics(metricsURL string, handler string, listHandlers bool, all bool, showExclusions bool) {
	// Fetch metrics
	metrics, err := fetchMetrics(metricsURL)
	if err != nil {
		fmt.Printf("Error fetching metrics: %v\n", err)
		return
	}

	// Get handlers
	handlers := extractHandlers(metrics)

	if listHandlers {
		fmt.Println("Available handlers:")
		for _, h := range handlers {
			fmt.Printf("  - %s\n", h)
		}
		return
	}

	// Show general metrics first
	if showExclusions {
		printGeneralStats(metrics)
	}

	if all {
		for _, h := range handlers {
			printHandlerStats(h, metrics)
		}
		if showExclusions {
			printExclusionStats(metrics)
		}
		return
	}

	if handler == "" && !showExclusions {
		fmt.Println("Please specify a handler with -handler or use -list to see available handlers")
		return
	}

	if handler != "" {
		if !contains(handlers, handler) {
			fmt.Printf("Handler %s not found. Available handlers:\n", handler)
			for _, h := range handlers {
				fmt.Printf("  - %s\n", h)
			}
			return
		}
		printHandlerStats(handler, metrics)
	}

	if showExclusions {
		printExclusionStats(metrics)
	}
}

func printGeneralStats(metrics []MetricSample) {
	totalEvents := make(map[string]float64)
	for _, m := range metrics {
		if m.Name == "bpfview_events_total" {
			if eventType, ok := m.Labels["event_type"]; ok {
				totalEvents[eventType] = m.Value
			}
		}
	}

	fmt.Printf("\nGeneral Statistics\n")
	fmt.Printf("===================\n")
	
	if len(totalEvents) > 0 {
		fmt.Printf("Total Events Processed:\n")
		var total float64
		for eventType, count := range totalEvents {
			fmt.Printf("  ├─ %s: %.0f\n", eventType, count)
			total += count
		}
		fmt.Printf("  └─ Total: %.0f\n", total)
	}
	
	// Add resource usage if available
	var goroutines, memory float64
	for _, m := range metrics {
		if m.Name == "bpfview_resource_usage" {
			if resource, ok := m.Labels["resource"]; ok {
				if resource == "goroutines" {
					goroutines = m.Value
				} else if resource == "memory_bytes" {
					memory = m.Value
				}
			}
		}
	}
	
	if goroutines > 0 || memory > 0 {
		fmt.Printf("\nResource Usage:\n")
		if goroutines > 0 {
			fmt.Printf("  ├─ Goroutines: %.0f\n", goroutines)
		}
		if memory > 0 {
			fmt.Printf("  └─ Memory: %.2f MB\n", memory/1024/1024)
		}
	}
}

func printExclusionStats(metrics []MetricSample) {
	stats := collectExclusionStats(metrics)

	fmt.Printf("\nExclusion Statistics\n")
	fmt.Printf("===================\n")
	fmt.Printf("Total Exclusions: %.0f\n", stats.Total)

	if len(stats.ByType) > 0 {
		fmt.Printf("\nExclusions by Type:\n")
		w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
		fmt.Fprintf(w, "  Rule Type\tPattern\tCount\t\n")
		fmt.Fprintf(w, "  ---------\t-------\t-----\t\n")
		
		// Sort rule types for consistent output
		ruleTypes := make([]string, 0, len(stats.ByType))
		for ruleType := range stats.ByType {
			ruleTypes = append(ruleTypes, ruleType)
		}
		sort.Strings(ruleTypes)
		
		for _, ruleType := range ruleTypes {
			patterns := stats.ByType[ruleType]
			
			// Sort patterns for consistent output
			patternList := make([]string, 0, len(patterns))
			for pattern := range patterns {
				patternList = append(patternList, pattern)
			}
			sort.Strings(patternList)
			
			for _, pattern := range patternList {
				count := patterns[pattern]
				fmt.Fprintf(w, "  %s\t%s\t%.0f\t\n", ruleType, pattern, count)
			}
		}
		w.Flush()
	}

	if len(stats.PatternCount) > 0 {
		fmt.Printf("\nActive Exclusion Patterns:\n")
		for typ, count := range stats.PatternCount {
			fmt.Printf("  ├─ %s: %.0f\n", typ, count)
		}
	}

	// Show histogram of exclusion latency if available
	var latencyBuckets = make(map[string]float64)
	for _, m := range metrics {
		if m.Name == "bpfview_exclusion_latency_seconds_bucket" {
			if le, ok := m.Labels["le"]; ok {
				latencyBuckets[le] = m.Value
			}
		}
	}
	
	if len(latencyBuckets) > 0 {
		fmt.Printf("\nExclusion Latency Distribution (microseconds):\n")
		printHistogram(latencyBuckets, 1000000) // Convert to microseconds
	}

	if stats.LatencyAvg > 0 {
		fmt.Printf("\nLatency Statistics:\n")
		fmt.Printf("  ├─ Average: %.3f μs\n", stats.LatencyAvg*1000000)
		fmt.Printf("  └─ Maximum: %.3f μs\n", stats.LatencyMax*1000000)
	}

	if len(stats.ExcludedEvents) > 0 {
		fmt.Printf("\nExcluded Events by Size:\n")
		fmt.Printf("  ├─ Average Size: %.0f bytes\n", stats.ExcludedEvents["avg"])
		fmt.Printf("  └─ Total Events: %.0f\n", stats.ExcludedEvents["count"])
	}
}

func printHistogram(buckets map[string]float64, multiplier float64) {
	// Sort bucket boundaries
	boundaries := make([]float64, 0, len(buckets))
	for le := range buckets {
		if le != "+Inf" {
			val, err := strconv.ParseFloat(le, 64)
			if err == nil {
				boundaries = append(boundaries, val)
			}
		}
	}
	sort.Float64s(boundaries)
	
	// Calculate bucket values (not cumulative)
	values := make([]float64, len(boundaries)+1)
	prevCount := 0.0
	
	for i, boundary := range boundaries {
		leStr := strconv.FormatFloat(boundary, 'f', -1, 64)
		count := buckets[leStr]
		values[i] = count - prevCount
		prevCount = count
	}
	
	// Inf bucket
	if infCount, ok := buckets["+Inf"]; ok {
		values[len(values)-1] = infCount - prevCount
	}
	
	// Print histogram
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "  Range\tCount\tHistogram\t\n")
	fmt.Fprintf(w, "  -----\t-----\t---------\t\n")
	
	maxCount := 0.0
	for _, v := range values {
		if v > maxCount {
			maxCount = v
		}
	}
	
	// Print first bucket
	if len(boundaries) > 0 {
		histStr := generateHistBar(values[0], maxCount, 40)
		fmt.Fprintf(w, "  < %.2f\t%.0f\t%s\t\n", boundaries[0]*multiplier, values[0], histStr)
	}
	
	// Print middle buckets
	for i := 0; i < len(boundaries)-1; i++ {
		histStr := generateHistBar(values[i+1], maxCount, 40)
		fmt.Fprintf(w, "  %.2f - %.2f\t%.0f\t%s\t\n", 
			boundaries[i]*multiplier, 
			boundaries[i+1]*multiplier, 
			values[i+1], 
			histStr)
	}
	
	// Print infinity bucket
	if len(boundaries) > 0 {
		histStr := generateHistBar(values[len(values)-1], maxCount, 40)
		fmt.Fprintf(w, "  > %.2f\t%.0f\t%s\t\n", 
			boundaries[len(boundaries)-1]*multiplier, 
			values[len(values)-1], 
			histStr)
	}
	
	w.Flush()
}

func generateHistBar(value, max float64, width int) string {
	if max == 0 {
		return ""
	}
	chars := int(value / max * float64(width))
	if chars < 1 && value > 0 {
		chars = 1
	}
	return strings.Repeat("█", chars)
}

func collectExclusionStats(metrics []MetricSample) ExclusionStats {
	stats := ExclusionStats{
		ByType:         make(map[string]map[string]float64),
		PatternCount:   make(map[string]float64),
		ExcludedEvents: make(map[string]float64),
	}

	for _, m := range metrics {
		switch {
		case m.Name == "bpfview_excluded_events_total":
			stats.Total += m.Value
			
			ruleType, hasRuleType := m.Labels["rule_type"]
			pattern, hasPattern := m.Labels["pattern"]
			
			if hasRuleType && hasPattern {
				if _, ok := stats.ByType[ruleType]; !ok {
					stats.ByType[ruleType] = make(map[string]float64)
				}
				stats.ByType[ruleType][pattern] = m.Value
			}

		case m.Name == "bpfview_exclusion_latency_seconds_sum":
			// Calculate average latency
			var count float64
			for _, m2 := range metrics {
				if m2.Name == "bpfview_exclusion_latency_seconds_count" && 
				   m2.Labels["pattern_type"] == m.Labels["pattern_type"] {
					count = m2.Value
					break
				}
			}
			if count > 0 {
				stats.LatencyAvg = m.Value / count
			}

		case m.Name == "bpfview_exclusion_latency_seconds_bucket":
			// Find max latency from histogram buckets
			if le, ok := m.Labels["le"]; ok && le != "+Inf" {
				if leVal, err := strconv.ParseFloat(le, 64); err == nil {
					if leVal > stats.LatencyMax {
						stats.LatencyMax = leVal
					}
				}
			}

		case m.Name == "bpfview_exclusion_patterns_total":
			if typ, ok := m.Labels["pattern_type"]; ok {
				stats.PatternCount[typ] = m.Value
			}

		case m.Name == "bpfview_excluded_event_size_bytes_sum":
			stats.ExcludedEvents["sum"] = m.Value
		case m.Name == "bpfview_excluded_event_size_bytes_count":
			stats.ExcludedEvents["count"] = m.Value
		}
	}

	// Calculate average event size
	if sum, ok := stats.ExcludedEvents["sum"]; ok {
		if count, ok := stats.ExcludedEvents["count"]; ok && count > 0 {
			stats.ExcludedEvents["avg"] = sum / count
		}
	}

	return stats
}

func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}

func printHandlerStats(handler string, metrics []MetricSample) {
	// Get handler stats
	var handlerCount, handlerSum float64
	for _, m := range metrics {
		if m.Name == "bpfview_handler_duration_seconds_count" &&
			m.Labels["handler"] == handler {
			handlerCount = m.Value
		}
		if m.Name == "bpfview_handler_duration_seconds_sum" &&
			m.Labels["handler"] == handler {
			handlerSum = m.Value
		}
	}

	if handlerCount == 0 {
		fmt.Printf("No data available for handler: %s\n", handler)
		return
	}

	avgHandlerTime := handlerSum / handlerCount

	// Get phase percentages and times
	type phaseInfo struct {
		name       string
		percentage float64
		avgTime    float64
		count      float64
	}

	phasePercentages := make(map[string]float64)
	phaseSums := make(map[string]float64)
	phaseCounts := make(map[string]float64)

	for _, m := range metrics {
		if m.Name == "bpfview_handler_phase_percentage" &&
			m.Labels["handler"] == handler {
			phasePercentages[m.Labels["phase"]] = m.Value
		}
		if m.Name == "bpfview_handler_phase_duration_seconds_sum" &&
			m.Labels["handler"] == handler {
			phaseSums[m.Labels["phase"]] = m.Value
		}
		if m.Name == "bpfview_handler_phase_duration_seconds_count" &&
			m.Labels["handler"] == handler {
			phaseCounts[m.Labels["phase"]] = m.Value
		}
	}

	phases := make([]phaseInfo, 0, len(phasePercentages))
	for phase, percentage := range phasePercentages {
		avgTime := 0.0
		count := 0.0
		if phaseCounts[phase] > 0 {
			avgTime = phaseSums[phase] / phaseCounts[phase]
			count = phaseCounts[phase]
		}
		phases = append(phases, phaseInfo{
			name:       phase,
			percentage: percentage,
			avgTime:    avgTime,
			count:      count,
		})
	}

	// Sort phases by percentage
	sort.Slice(phases, func(i, j int) bool {
		return phases[i].percentage > phases[j].percentage
	})

	// Print results
	fmt.Printf("\n%s Handler Timing Breakdown\n", strings.Title(handler))
	fmt.Printf("=====================================\n")
	fmt.Printf("%s: avg=%.3fms (count=%.0f)\n", handler, avgHandlerTime*1000, handlerCount)

	// Use tabwriter for better alignment
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(w, "  Phase\tAvg Time\tPercentage\tCount\t\n")
	fmt.Fprintf(w, "  -----\t--------\t----------\t-----\t\n")
	
	for _, phase := range phases {
		fmt.Fprintf(w, "  %s\t%.3fms\t%.1f%%\t%.0f\t\n", 
			phase.name, 
			phase.avgTime*1000, 
			phase.percentage,
			phase.count)
	}
	w.Flush()
}

func extractHandlers(metrics []MetricSample) []string {
	handlerSet := make(map[string]bool)
	for _, m := range metrics {
		if m.Name == "bpfview_handler_duration_seconds_count" {
			if handler, ok := m.Labels["handler"]; ok {
				handlerSet[handler] = true
			}
		}
	}

	handlers := make([]string, 0, len(handlerSet))
	for handler := range handlerSet {
		handlers = append(handlers, handler)
	}
	sort.Strings(handlers)
	return handlers
}

func fetchMetrics(url string) ([]MetricSample, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	return parseMetrics(resp.Body)
}

func parseMetrics(r io.Reader) ([]MetricSample, error) {
	scanner := bufio.NewScanner(r)
	var metrics []MetricSample

	// Regular expressions for parsing metrics
	metricLine := regexp.MustCompile(`^([a-zA-Z_:][a-zA-Z0-9_:]*)\{([^}]*)\} (.+)$`)
	metricSimple := regexp.MustCompile(`^([a-zA-Z_:][a-zA-Z0-9_:]*) (.+)$`)
	labelPair := regexp.MustCompile(`([a-zA-Z_][a-zA-Z0-9_]*)="([^"]*)"`)

	for scanner.Scan() {
		line := scanner.Text()

		// Skip comments and empty lines
		if strings.HasPrefix(line, "#") || line == "" {
			continue
		}

		// Try to match with labels
		if matches := metricLine.FindStringSubmatch(line); len(matches) == 4 {
			name := matches[1]
			labelsStr := matches[2]
			valueStr := matches[3]

			value, err := strconv.ParseFloat(valueStr, 64)
			if err != nil {
				continue // Skip if we can't parse the value
			}

			// Parse labels
			labels := make(map[string]string)
			labelMatches := labelPair.FindAllStringSubmatch(labelsStr, -1)
			for _, labelMatch := range labelMatches {
				labels[labelMatch[1]] = labelMatch[2]
			}

			metrics = append(metrics, MetricSample{
				Name:   name,
				Labels: labels,
				Value:  value,
			})
		} else if matches := metricSimple.FindStringSubmatch(line); len(matches) == 3 {
			// Simple metric without labels
			name := matches[1]
			valueStr := matches[2]

			value, err := strconv.ParseFloat(valueStr, 64)
			if err != nil {
				continue // Skip if we can't parse the value
			}

			metrics = append(metrics, MetricSample{
				Name:   name,
				Labels: make(map[string]string),
				Value:  value,
			})
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return metrics, nil
}

func clearScreen() {
	fmt.Print("\033[H\033[2J")
}
