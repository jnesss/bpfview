package main

import (
    "sync"
)

type ProcessTree struct {
    processes map[uint32]*ProcessInfo
    children  map[uint32]map[uint32]bool  // PPID -> set of child PIDs
    roots     map[uint32]bool             // PIDs we're tracking as roots
    mu        sync.RWMutex
}

func NewProcessTree() *ProcessTree {
    return &ProcessTree{
        processes: make(map[uint32]*ProcessInfo),
        children:  make(map[uint32]map[uint32]bool),
        roots:     make(map[uint32]bool),
    }
}

func (pt *ProcessTree) AddProcess(info *ProcessInfo) {
    pt.mu.Lock()
    defer pt.mu.Unlock()

    pt.processes[info.PID] = info
    
    // Add to children map
    if pt.children[info.PPID] == nil {
        pt.children[info.PPID] = make(map[uint32]bool)
    }
    pt.children[info.PPID][info.PID] = true
}

func (pt *ProcessTree) AddRoot(pid uint32) {
    pt.mu.Lock()
    defer pt.mu.Unlock()
    pt.roots[pid] = true
}

func (pt *ProcessTree) IsInTree(pid uint32) bool {
    pt.mu.RLock()
    defer pt.mu.RUnlock()

    // Is it a root?
    if pt.roots[pid] {
        return true
    }

    // Walk up the process tree to see if we hit a root
    current := pid
    visited := make(map[uint32]bool) // Prevent cycles

    for {
        if visited[current] {
            return false // Cycle detected
        }
        visited[current] = true

        info := pt.processes[current]
        if info == nil {
            return false
        }

        if pt.roots[info.PPID] {
            return true // Found a root ancestor
        }

        if info.PPID == 0 {
            return false // Hit init without finding a root
        }

        current = info.PPID
    }
}
