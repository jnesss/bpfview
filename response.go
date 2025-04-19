package main

import (
	"fmt"
	"time"
)

// ResponseManager handles applying restrictions to processes
type ResponseManager struct {
	objs *responseObjects
}

// NewResponseManager creates a new ResponseManager
func NewResponseManager(objs *responseObjects) *ResponseManager {
	return &ResponseManager{
		objs: objs,
	}
}

// ApplyRestrictions applies the specified restrictions to a process
func (rm *ResponseManager) ApplyRestrictions(pid uint32, flags uint32) error {
	restrictions := struct {
		Flags     uint32
		Padding   uint32
		Timestamp uint64
	}{
		Flags:     flags,
		Timestamp: uint64(time.Now().Unix()),
	}

	// Apply restrictions
	if err := rm.objs.RestrictedProcs.Put(pid, &restrictions); err != nil {
		return fmt.Errorf("putting restrictions: %w", err)
	}

	// Verify they were applied
	var stored struct {
		Flags     uint32
		Padding   uint32
		Timestamp uint64
	}
	if err := rm.objs.RestrictedProcs.Lookup(pid, &stored); err != nil {
		return fmt.Errorf("verifying restrictions: %w", err)
	}

	globalLogger.Debug("response", "Applied restrictions to PID %d: Flags=0x%x", pid, stored.Flags)
	return nil
}

// RemoveRestrictions removes all restrictions from a process
func (rm *ResponseManager) RemoveRestrictions(pid uint32) error {
	if err := rm.objs.RestrictedProcs.Delete(pid); err != nil {
		return fmt.Errorf("removing restrictions: %w", err)
	}

	globalLogger.Debug("response", "Removed all restrictions from PID %d", pid)
	return nil
}

// GetRestrictions gets the current restrictions for a process
func (rm *ResponseManager) GetRestrictions(pid uint32) (uint32, error) {
	var restrictions struct {
		Flags     uint32
		Padding   uint32
		Timestamp uint64
	}

	if err := rm.objs.RestrictedProcs.Lookup(pid, &restrictions); err != nil {
		return 0, fmt.Errorf("looking up restrictions: %w", err)
	}

	return restrictions.Flags, nil
}
