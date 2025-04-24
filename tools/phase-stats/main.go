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
)

type MetricSample struct {
	Name   string
	Labels map[string]string
	Value  float64
}

func main() {
	metricsURL := flag.String("url", "http://localhost:2112/metrics", "URL to fetch Prometheus metrics from")
	handler := flag.String("handler", "", "Handler to analyze (process_exec, process_fork, process_exit, dns_event, network_event, tls_event)")
	listHandlers := flag.Bool("list", false, "List all available handlers")
	all := flag.Bool("all", false, "Show stats for all handlers")
	flag.Parse()

	// Fetch metrics
	metrics, err := fetchMetrics(*metricsURL)
	if err != nil {
		fmt.Printf("Error fetching metrics: %v\n", err)
		return
	}

	// Get handlers
	handlers := extractHandlers(metrics)

	if *listHandlers {
		fmt.Println("Available handlers:")
		for _, h := range handlers {
			fmt.Printf("  - %s\n", h)
		}
		return
	}

	if *all {
		for _, h := range handlers {
			printHandlerStats(h, metrics)
		}
		return
	}

	if *handler == "" {
		fmt.Println("Please specify a handler with -handler or use -list to see available handlers")
		return
	}

	if !contains(handlers, *handler) {
		fmt.Printf("Handler %s not found. Available handlers:\n", *handler)
		for _, h := range handlers {
			fmt.Printf("  - %s\n", h)
		}
		return
	}

	printHandlerStats(*handler, metrics)
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
		if phaseCounts[phase] > 0 {
			avgTime = phaseSums[phase] / phaseCounts[phase]
		}
		phases = append(phases, phaseInfo{
			name:       phase,
			percentage: percentage,
			avgTime:    avgTime,
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

	for i, phase := range phases {
		prefix := "  ├─ "
		if i == len(phases)-1 {
			prefix = "  └─ "
		}
		fmt.Printf("%s%s: avg=%.3fms (%.1f%%)\n", 
			prefix, 
			phase.name, 
			phase.avgTime*1000, 
			phase.percentage)
	}
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
