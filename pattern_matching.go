// pattern_matching.go
package main

import (
	"path/filepath"
	"strings"
	"sync"
)

type PatternMatcher struct {
	mu sync.RWMutex

	// Exact matches (fastest)
	exactMatches map[string]struct{}

	// Glob patterns
	globPatterns []string

	// Prefix matches
	prefixMatches []string
}

func NewPatternMatcher(patterns []string) *PatternMatcher {
	pm := &PatternMatcher{
		exactMatches: make(map[string]struct{}),
	}

	for _, pattern := range patterns {
		if strings.ContainsAny(pattern, "*?[]") {
			// Glob pattern
			pm.globPatterns = append(pm.globPatterns, pattern)
		} else if strings.HasSuffix(pattern, "/") {
			// Prefix match (for paths)
			pm.prefixMatches = append(pm.prefixMatches, strings.TrimSuffix(pattern, "/"))
		} else {
			// Exact match
			pm.exactMatches[pattern] = struct{}{}
		}
	}

	return pm
}

func (pm *PatternMatcher) Matches(s string) bool {
	pm.mu.RLock()
	defer pm.mu.RUnlock()

	// Try exact match first (fastest)
	if _, ok := pm.exactMatches[s]; ok {
		return true
	}

	// Try prefix matches next
	for _, prefix := range pm.prefixMatches {
		if strings.HasPrefix(s, prefix) {
			return true
		}
	}

	// Try glob patterns last (most expensive)
	for _, pattern := range pm.globPatterns {
		matched, err := filepath.Match(pattern, s)
		if err == nil && matched {
			return true
		}
	}

	return false
}

func (pm *PatternMatcher) Add(pattern string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if strings.ContainsAny(pattern, "*?[]") {
		pm.globPatterns = append(pm.globPatterns, pattern)
	} else if strings.HasSuffix(pattern, "/") {
		pm.prefixMatches = append(pm.prefixMatches, strings.TrimSuffix(pattern, "/"))
	} else {
		pm.exactMatches[pattern] = struct{}{}
	}
}

func (pm *PatternMatcher) Remove(pattern string) {
	pm.mu.Lock()
	defer pm.mu.Unlock()

	if strings.ContainsAny(pattern, "*?[]") {
		for i, p := range pm.globPatterns {
			if p == pattern {
				pm.globPatterns = append(pm.globPatterns[:i], pm.globPatterns[i+1:]...)
				break
			}
		}
	} else if strings.HasSuffix(pattern, "/") {
		trimmed := strings.TrimSuffix(pattern, "/")
		for i, p := range pm.prefixMatches {
			if p == trimmed {
				pm.prefixMatches = append(pm.prefixMatches[:i], pm.prefixMatches[i+1:]...)
				break
			}
		}
	} else {
		delete(pm.exactMatches, pattern)
	}
}
