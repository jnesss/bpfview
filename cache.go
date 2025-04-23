// cache.go
package main

import (
	"github.com/dgraph-io/ristretto"
	"github.com/jnesss/bpfview/types"
)

// ProcessCache wraps Ristretto cache for process information
type ProcessCache struct {
	cache   *ristretto.Cache
	maxSize int64
}

// NewProcessCache creates a new Ristretto-backed process cache
func NewProcessCache(maxSize int64) (*ProcessCache, error) {
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
		cache:   cache,
		maxSize: maxSize,
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
	return pc.cache.Set(pid, info, 1)
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

// GetSize returns current number of items in cache
func (pc *ProcessCache) GetSize() uint64 {
	if pc.cache == nil {
		return 0
	}
	metrics := pc.cache.Metrics
	if metrics == nil {
		return 0
	}
	return metrics.KeysAdded() - metrics.KeysEvicted()
}

// GetMetrics returns current cache metrics
func (pc *ProcessCache) GetMetrics() *ristretto.Metrics {
	return pc.cache.Metrics
}

// Wait ensures all pending operations are complete
func (pc *ProcessCache) Wait() {
	pc.cache.Wait()
}
