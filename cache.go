// cache.go
package main

import (
	"time"

	"github.com/dgraph-io/ristretto"
	"github.com/jnesss/bpfview/types"
)

// ProcessCache wraps Ristretto cache for process information
type ProcessCache struct {
	cache      *ristretto.Cache
	maxSize    int64
	defaultTTL time.Duration
}

// NewProcessCache creates a new Ristretto-backed process cache
func NewProcessCache(maxSize int64, ttl time.Duration) (*ProcessCache, error) {
	cfg := &ristretto.Config{
		NumCounters: maxSize * 10,
		MaxCost:     maxSize,
		BufferItems: 64,
		Metrics:     true,
		Cost: func(value interface{}) int64 {
			if pi, ok := value.(*types.ProcessInfo); ok {
				size := int64(24)
				size += int64(len(pi.Comm) + len(pi.ParentComm) +
					len(pi.ExePath) + len(pi.CmdLine) +
					len(pi.WorkingDir) + len(pi.Username) +
					len(pi.ContainerID) + len(pi.ProcessUID))

				for _, env := range pi.Environment {
					size += int64(len(env))
				}
				return size
			}
			return 1
		},
	}

	cache, err := ristretto.NewCache(cfg)
	if err != nil {
		return nil, err
	}

	return &ProcessCache{
		cache:      cache,
		maxSize:    maxSize,
		defaultTTL: ttl,
	}, nil
}

// Get retrieves a process from the cache
func (pc *ProcessCache) Get(pid uint32) (*types.ProcessInfo, bool) {
	value, found := pc.cache.Get(pid)
	if !found {
		return nil, false
	}
	return value.(*types.ProcessInfo), true
}

// Set adds or updates a process in the cache
func (pc *ProcessCache) Set(pid uint32, info *types.ProcessInfo) bool {
	return pc.cache.SetWithTTL(pid, info, 1, pc.defaultTTL)
}

// Delete removes a process from the cache
func (pc *ProcessCache) Delete(pid uint32) {
	pc.cache.Del(pid)
}

// Clear removes all processes from the cache
func (pc *ProcessCache) Clear() {
	pc.cache.Clear()
}

// MaxSize returns the configured maximum cache size
func (pc *ProcessCache) MaxSize() int64 {
	return pc.maxSize
}

// GetMetrics returns current cache metrics
func (pc *ProcessCache) GetMetrics() *ristretto.Metrics {
	return pc.cache.Metrics
}

// Wait ensures all pending operations are complete
func (pc *ProcessCache) Wait() {
	pc.cache.Wait()
}
