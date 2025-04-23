package main

import (
	"bytes"
	"fmt"
	"hash/fnv"
	"io/ioutil"
	"log"
	"os"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/jnesss/bpfview/types"

	"github.com/prometheus/client_golang/prometheus"
)

// Process cache to maintain state
var processCache *ProcessCache

// Username cache to avoid repeated lookups
var (
	usernameCacheMutex sync.RWMutex
	usernameCache      = make(map[uint32]string)
)

// Container ID regex for detection
var containerIDRegex = regexp.MustCompile(`^[a-f0-9]{12,64}$`)

var ignoreExitProcesses = map[string]bool{
	// Kernel worker threads
	"kworker/":   true, // All kernel worker threads
	"kthread":    true, // Kernel thread parent
	"ksoftirqd/": true, // Kernel softirq daemon
	"migration/": true, // CPU migration threads
	"cpuhp/":     true, // CPU hotplug threads
	"watchdog/":  true, // Kernel watchdog threads
	"irq/":       true, // Interrupt request threads
	"xenwatch":   true, // Xen hypervisor watches
	"xenbus":     true, // Xen bus threads

	// Kernel service threads
	"jbd2/":       true, // Journal block device
	"kauditd":     true, // Kernel audit daemon
	"kblockd":     true, // Block device threads
	"kswapd":      true, // Kernel swap daemon
	"ecryptfs":    true, // Encrypted filesystem threads
	"kintegrityd": true, // Data integrity threads
	"khungtaskd":  true, // Hung task detector
	"kcompactd":   true, // Memory compaction
	"kdevtmpfs":   true, // Device tmpfs handler
	"writeback":   true, // Memory writeback
	"crypto":      true, // Crypto threads
	"bioset":      true, // Bio set threads
	"kverityd":    true, // Kernel verity

	// Special pseudo-processes
	"idle":                true, // CPU idle process (PID 0)
	"ext4-rsv-conversion": true, // Filesystem operations
	"loop":                true, // Loop device handler
	"nfsd":                true, // NFS daemon kernel threads

	// Kernel networking threads
	"ksmd":          true,
	"khugepaged":    true,
	"ipv6_addrconf": true, // IPv6 address configuration

	// Various daemon handler threads that spawn from kernel
	"deferwq":   true, // Deferred work queue
	"scsi_eh_":  true, // SCSI error handler
	"scsi_tmf_": true, // SCSI TMF handler

	// Special process states
	"kworker/dying": true, // Dying worker threads

	// Journal processes spawned by kernel
	"journal":         true,
	"journal-offline": true,

	// Others
	"edac-poller":     true, // Error detection and correction
	"acpi_thermal_pm": true, // ACPI thermal management
	"ktpacpid":        true, // ACPI thread
	"kstrp":           true, // Stream parser
}

func handleProcessEvent(event *types.ProcessEvent, bpfObjs *execveObjects) {
	if event.EventType == types.EVENT_PROCESS_EXEC {
		handleProcessExecEvent(event, bpfObjs)
	} else if event.EventType == types.EVENT_PROCESS_EXIT {
		handleProcessExitEvent(event)
	} else if event.EventType == types.EVENT_PROCESS_FORK {
		handleProcessForkEvent(event)
	}
}

func handleProcessExitEvent(event *types.ProcessEvent) {
	// Check if we should ignore this exit
	comm := string(bytes.TrimRight(event.Comm[:], "\x00"))
	if shouldIgnoreProcessExit(comm) {
		return
	}

	timer := NewEventTimer("process_exit")

	// Record event count
	eventCounter.WithLabelValues("process").Inc()

	// Get the process from cache
	info, exists := GetProcessFromCache(event.Pid)
	if !exists {
		// Process not in cache, nothing to update
		//  (we could try to update based on comm + PID but we wouldn't have UID..)
		timer.ObserveDuration()
		return
	}

	// Only update if we haven't recorded an exit time yet
	if !info.ExitTime.IsZero() {
		// Already has exit time, skip
		timer.ObserveDuration()
		return
	}

	info.ExitTime = BpfTimestampToTime(event.Timestamp)
	info.ExitCode = event.ExitCode
	info.EventType = "exit" // Update the event type

	// Update the process in cache
	AddOrUpdateProcessCache(event.Pid, info)

	// Debug log for event details
	globalLogger.Trace("process", "Processing EXIT event for PID %d\n", event.Pid)
	globalLogger.Trace("process", "BPF data - Comm: %s, UID: %d, GID: %d\n",
		string(bytes.TrimRight(event.Comm[:], "\x00")),
		event.Uid,
		event.Gid)

	// Filter check AFTER enrichment and cache updates, but BEFORE logging
	if globalEngine != nil && !globalEngine.ShouldLog(info) {
		excludedEventsTotal.WithLabelValues("process_exit").Inc()
		timer.ObserveDuration()
		return
	}

	// For EXIT events
	parentComm := string(bytes.TrimRight(event.ParentComm[:], "\x00"))
	var msg strings.Builder
	fmt.Fprintf(&msg, "EXIT: PID=%d comm=%s\n", info.PID, info.Comm)
	fmt.Fprintf(&msg, "      Parent: [%d] %s\n", info.PPID, parentComm)
	fmt.Fprintf(&msg, "      User: %s (%d/%d)\n", info.Username, info.UID, info.GID)
	fmt.Fprintf(&msg, "      Exit Code: %d", info.ExitCode)

	// Add duration if available
	if !info.StartTime.IsZero() && !info.ExitTime.IsZero() {
		duration := info.ExitTime.Sub(info.StartTime)
		fmt.Fprintf(&msg, "\n      Duration: %s", duration)
	}

	globalLogger.Info("process", "%s", msg.String())

	var parentinfo *types.ProcessInfo
	if pinfo, exists := GetProcessFromCache(info.PPID); exists {
		parentinfo = pinfo
	} else {
		parentinfo = &types.ProcessInfo{
			PID:  info.PPID,
			Comm: string(bytes.TrimRight(event.ParentComm[:], "\x00")),
		}
	}

	// Log to file with proper structured format if logger is available
	if globalLogger != nil {
		globalLogger.LogProcess(event, info, parentinfo)
	}

	// End timer before the sleep
	timer.ObserveDuration()

	// Remove process from cache one second later after processing EXIT
	//  This delay preserves the cache for a process exec that might come out of order
	time.Sleep(1 * time.Second)

	if processCache != nil {
		processCache.Delete(event.Pid)
	}
}

/*
ProcessCache Strategy

The process cache is used to maintain state about running processes, particularly parent-child
relationships. The main challenges are:

1. Race Conditions:
   - Fork events can arrive before parent process info is fully cached
   - Cache operations (Set) are asynchronous and need Wait() to ensure completion
   - Multiple goroutines may try to cache the same parent process

2. Process State:
   - Process state may not be immediately available after fork
   - Parent processes may exit while children are still running
   - Some process info comes from BPF, some from /proc filesystem

Caching Strategy:
1. Fast Path: Try immediate cache lookup first
2. Recovery Path: On first miss, try loading from /proc
3. Retry Path: Use short exponential backoff for subsequent attempts
4. Verification: Always verify cache operations complete and succeeded

This strategy balances performance (most processes hit the fast path) with reliability
(we'll eventually get the data even in edge cases).
*/

func handleProcessForkEvent(event *types.ProcessEvent) {
	timers := NewTimerPair("process_fork")
	defer timers.ObserveDuration()

	// Debug logging
	globalLogger.Trace("process", "Processing FORK event for PID %d\n", event.Pid)

	// Create basic info from kernel event
	info := &types.ProcessInfo{
		PID:        event.Pid,
		PPID:       event.Ppid,
		Comm:       string(bytes.TrimRight(event.Comm[:], "\x00")),
		ParentComm: string(bytes.TrimRight(event.ParentComm[:], "\x00")),
		UID:        event.Uid,
		GID:        event.Gid,
		StartTime:  BpfTimestampToTime(event.Timestamp),
		EventType:  "fork",
	}

	// Try to get parent info with exponential backoff
	var parentInfo *types.ProcessInfo
	var parentExists bool

	for attempt := 0; attempt < 4; attempt++ { // Max 15ms total (1+2+4+8)
		timers.IncrementAttempts()

		// Fast Path: Try cache first
		if pinfo, exists := GetProcessFromCache(event.Ppid); exists {
			parentInfo = pinfo
			parentExists = true
			break
		}

		// Recovery Path: On first failure, try loading from /proc
		if attempt == 0 {
			if pinfo := findAndCacheParentProcess(event.Ppid); pinfo != nil {
				// Wait for cache operation to complete
				processCache.cache.Wait()

				// Verify the cache operation succeeded
				if pinfo, exists := GetProcessFromCache(event.Ppid); exists {
					parentInfo = pinfo
					parentExists = true
					break
				}
			}
		}

		// Retry Path: Exponential backoff before next attempt
		delay := time.Duration(1<<uint(attempt)) * time.Millisecond
		time.Sleep(delay)
	}

	// If we still failed, log diagnostic info
	if !parentExists {
		globalLogger.Info("process", "Failed to find parent after all attempts: "+
			"Child PID=%d comm=%s, Parent PID=%d", event.Pid, info.Comm, event.Ppid)
	}

	timers.StartProcessing(parentExists)
	eventCounter.WithLabelValues("process").Inc()

	// Inherit parent info if found
	if parentExists {
		InheritFromParent(info, parentInfo)
	}

	// Complete process info and cache the new process
	//  Using types.ProcessLevel Minimal here because:
	//  1. All basic info comes from the kernel event
	//  2. Everything else is inherited from parent if available
	//  3. We don't need to read /proc because either:
	//     Parent info exists and we inherit
	//     Parent info doesn't exist and retrying won't help
	CompleteProcessInfo(info, types.ProcessLevelMinimal)
	success := AddOrUpdateProcessCache(event.Pid, info)
	if !success {
		globalLogger.Debug("process", "Failed to cache new process PID %d", event.Pid)
	}

	// Add to process tree if exists
	if globalEngine != nil {
		globalEngine.processTree.AddProcess(info)
	}

	// Filter check AFTER enrichment and cache updates, but BEFORE logging
	if globalEngine != nil && !globalEngine.ShouldLog(info) {
		excludedEventsTotal.WithLabelValues("process_fork").Inc()
		return
	}

	// Log to console with enhanced information
	parentComm := string(bytes.TrimRight(event.ParentComm[:], "\x00"))

	// Build the message using strings.Builder - same pattern as handleProcessExecEvent
	var msg strings.Builder
	fmt.Fprintf(&msg, "FORK: PID=%d comm=%s ProcessUID=%s\n", info.PID, info.Comm, info.ProcessUID)
	fmt.Fprintf(&msg, "      Parent: [%d] %s\n", info.PPID, parentComm)
	fmt.Fprintf(&msg, "      User: %s (%d/%d)\n", info.Username, info.UID, info.GID)

	if info.ExePath != "" {
		fmt.Fprintf(&msg, "      Path: %s", info.ExePath)
		if parentExists {
			fmt.Fprintf(&msg, " (inherited)")
		}
	}

	if info.WorkingDir != "" {
		fmt.Fprintf(&msg, "\n      CWD: %s", info.WorkingDir)
		if parentExists {
			fmt.Fprintf(&msg, " (inherited)")
		}
	}

	if info.CmdLine != "" {
		fmt.Fprintf(&msg, "\n      Command: %s", sanitizeCommandLine(info.CmdLine))
		if parentExists {
			fmt.Fprintf(&msg, " (inherited)")
		}
	}

	if info.ContainerID != "" && info.ContainerID != "-" {
		fmt.Fprintf(&msg, "\n      Container: %s", info.ContainerID)
		if parentExists {
			fmt.Fprintf(&msg, " (inherited)")
		}
	}

	globalLogger.Info("process", "%s", msg.String())

	// BUG:  This is NOT handling FORK-EXEC well.  Need to optimize this!!
	// Log to file with proper structured format if logger is available
	if globalLogger != nil {
		if !parentExists {
			// Create an empty parent info object if parent wasn't found
			parentInfo = &types.ProcessInfo{}
		}
		globalLogger.LogProcess(event, info, parentInfo)
	}

	// If Sigma detection is enabled, submit event - same as handleProcessExecEvent
	if globalSigmaEngine != nil {
		// Include core fields needed for Sigma rule matching
		sigmaEvent := map[string]interface{}{
			"Image":            info.ExePath,
			"CmdLine":          info.CmdLine,
			"ProcessName":      info.Comm,
			"ParentProcessId":  info.PPID,
			"User":             info.Username,
			"CurrentDirectory": info.WorkingDir,
			"EventType":        "fork",
		}

		// Create detection event
		detectionEvent := DetectionEvent{
			EventType:       "process_creation",
			Data:            sigmaEvent,
			Timestamp:       BpfTimestampToTime(event.Timestamp),
			ProcessUID:      info.ProcessUID,
			PID:             info.PID,
			DetectionSource: "process_creation",
		}

		// Submit non-blocking
		globalSigmaEngine.SubmitEvent(detectionEvent)
	}
}

func handleProcessExecEvent(event *types.ProcessEvent, bpfObjs *execveObjects) {
	timers := NewTimerPair("process_exec")
	defer timers.ObserveDuration()

	// Debug logging
	globalLogger.Trace("process", "Processing EXEC event for PID %d\n", event.Pid)

	// Create basic info from kernel event
	info := &types.ProcessInfo{
		PID:        event.Pid,
		PPID:       event.Ppid,
		Comm:       string(bytes.TrimRight(event.Comm[:], "\x00")),
		ParentComm: string(bytes.TrimRight(event.ParentComm[:], "\x00")),
		UID:        event.Uid,
		GID:        event.Gid,
		StartTime:  BpfTimestampToTime(event.Timestamp),
		EventType:  "exec",
	}

	// Get executable path from kernel data if available
	if len(event.ExePath) > 0 {
		kernelExePath := string(bytes.TrimRight(event.ExePath[:], "\x00"))
		if kernelExePath != "" {
			info.ExePath = kernelExePath
			globalLogger.Trace("process", "PID %d: Got ExePath from BPF: [%v]\n", event.Pid, info.ExePath)
		}
	}

	// Get command line from BPF map if available
	if bpfObjs != nil {
		if cmdline, err := LookupCmdline(bpfObjs, event.Pid); err == nil && cmdline != "" {
			info.CmdLine = cmdline
			globalLogger.Trace("process", "PID %d: Got CmdLine from BPF: [%v]\n", event.Pid, info.CmdLine)
		}
	}

	// First /proc check - may catch the process before exec is complete
	timers.IncrementAttempts()
	firstProcInfo := CollectProcMetadata(event.Pid)
	MergeProcessInfo(info, firstProcInfo, "first")

	// Set username based on current UID
	info.Username = GetUsernameFromUID(info.UID)

	// Wait briefly for exec to complete
	timers.IncrementAttempts()
	time.Sleep(2 * time.Millisecond)

	// Second /proc check - this should have the final state
	timers.IncrementAttempts()
	secondProcInfo := CollectProcMetadata(event.Pid)

	// Now we're done with waits, start processing timer
	timers.StartProcessing(true)

	MergeProcessInfo(info, secondProcInfo, "second")

	// Apply standard enrichment and finalization
	CompleteProcessInfo(info, types.ProcessLevelFull)

	// Add to process cache
	AddOrUpdateProcessCache(event.Pid, info)

	if globalEngine != nil {
		globalEngine.processTree.AddProcess(info)
	}

	// Filter check AFTER enrichment and cache updates, but BEFORE logging
	if globalEngine != nil && !globalEngine.ShouldLog(info) {
		excludedEventsTotal.WithLabelValues("process_exec").Inc()
		return
	}

	// Record event
	eventCounter.WithLabelValues("process").Inc()

	// Log to console with enhanced information
	parentComm := string(bytes.TrimRight(event.ParentComm[:], "\x00"))

	// Build the message using strings.Builder
	var msg strings.Builder
	fmt.Fprintf(&msg, "EXEC: PID=%d comm=%s ProcessUID=%s\n", info.PID, info.Comm, info.ProcessUID)
	fmt.Fprintf(&msg, "      Parent: [%d] %s\n", info.PPID, parentComm)
	fmt.Fprintf(&msg, "      User: %s (%d/%d)\n", info.Username, info.UID, info.GID)
	fmt.Fprintf(&msg, "      Path: %s", info.ExePath)
	if info.WorkingDir != "" {
		fmt.Fprintf(&msg, "\n      CWD: %s", info.WorkingDir)
	}
	if info.CmdLine != "" {
		fmt.Fprintf(&msg, "\n      Command: %s", sanitizeCommandLine(info.CmdLine))
	}
	if info.ContainerID != "" && info.ContainerID != "-" {
		fmt.Fprintf(&msg, "\n      Container: %s", info.ContainerID)
	}

	globalLogger.Info("process", "%s", msg.String())

	var parentinfo *types.ProcessInfo
	if pinfo, exists := GetProcessFromCache(event.Ppid); exists {
		parentinfo = pinfo
	} else {
		// Try to find and cache the missing parent
		parentinfo = findAndCacheParentProcess(event.Ppid)
		if parentinfo == nil {
			// If still not found, create minimal version
			parentinfo = &types.ProcessInfo{
				PID:  event.Ppid,
				Comm: string(bytes.TrimRight(event.ParentComm[:], "\x00")),
			}
		}
	}

	// Log to file with proper structured format if logger is available
	if globalLogger != nil {
		globalLogger.LogProcess(event, info, parentinfo)
	}

	// If Sigma detection is enabled, submit event
	if globalSigmaEngine != nil {
		// Include core fields needed for Sigma rule matching
		sigmaEvent := map[string]interface{}{
			"Image":            info.ExePath,
			"CmdLine":          info.CmdLine,
			"ProcessName":      info.Comm,
			"ParentProcessId":  info.PPID,
			"User":             info.Username,
			"CurrentDirectory": info.WorkingDir,
			"EventType":        "exec",
		}

		// Create detection event
		detectionEvent := DetectionEvent{
			EventType:       "process_creation",
			Data:            sigmaEvent,
			Timestamp:       BpfTimestampToTime(event.Timestamp),
			ProcessUID:      info.ProcessUID,
			PID:             info.PID,
			DetectionSource: "process_creation",
		}

		globalLogger.Trace("sigma", "Process creation event for PID %d: ProcessName=%s, Image=%s",
			info.PID, sigmaEvent["ProcessName"], sigmaEvent["Image"])

		// Submit non-blocking
		globalSigmaEngine.SubmitEvent(detectionEvent)
	}
}

// loadExecveProgram loads the process execution monitoring BPF program
func loadExecveProgram() execveObjects {
	objs := execveObjects{}
	if err := loadExecveObjects(&objs, nil); err != nil {
		log.Fatalf("loading execve objects: %v", err)
	}
	return objs
}

// AddOrUpdateProcessCache adds or updates a process in the cache
func AddOrUpdateProcessCache(pid uint32, info *types.ProcessInfo) bool {
	if processCache != nil {
		success := processCache.cache.Set(pid, info, 1)
		processCache.cache.Wait() // Ensure operation completes
		return success
	}
	return false
}

// GetProcessFromCache retrieves process info from the cache
func GetProcessFromCache(pid uint32) (*types.ProcessInfo, bool) {
	if processCache == nil {
		operationResults.WithLabelValues("process", "cache_lookup", "failure").Inc()
		cacheMisses.WithLabelValues("process").Inc()
		return nil, false
	}
	info, exists := processCache.Get(pid)
	if exists {
		operationResults.WithLabelValues("process", "cache_lookup", "success").Inc()
	} else {
		operationResults.WithLabelValues("process", "cache_lookup", "failure").Inc()
		cacheMisses.WithLabelValues("process").Inc()
	}
	return info, exists
}

// GetUsernameFromUID returns the username for a given UID
func GetUsernameFromUID(uid uint32) string {
	// Special case for root
	if uid == 0 {
		return "root"
	}

	// Check cache first
	usernameCacheMutex.RLock()
	if username, ok := usernameCache[uid]; ok {
		usernameCacheMutex.RUnlock()
		return username
	}
	usernameCacheMutex.RUnlock()

	// Not in cache, look it up
	if u, err := user.LookupId(fmt.Sprintf("%d", uid)); err == nil {
		usernameCacheMutex.Lock()
		usernameCache[uid] = u.Username
		usernameCacheMutex.Unlock()
		return u.Username
	}
	return ""
}

// Merge information into baseInfo with awareness of execution phases
func MergeProcessInfo(baseInfo *types.ProcessInfo, procInfo *types.ProcessInfo, phase string) {
	// Trust /proc Comm after 2ms more than BPF Comm
	if procInfo.Comm != "" && phase == "second" {
		globalLogger.Trace("process", "PID %d: Updating Comm from second check: [%v] -> [%v]\n",
			baseInfo.PID, baseInfo.Comm, procInfo.Comm)
		baseInfo.Comm = procInfo.Comm
	}

	// Handle ExePath merging
	if procInfo.ExePath != "" {
		if baseInfo.ExePath == "" {
			// If we don't have an ExePath yet, use anything we can get
			globalLogger.Trace("process", "PID %d: Adding ExePath from %s check: [%v]\n",
				baseInfo.PID, phase, procInfo.ExePath)
			baseInfo.ExePath = procInfo.ExePath

		} else if baseInfo.ExePath == procInfo.ExePath {
			// Both are the same, nothing to do
			globalLogger.Trace("process", "PID %d: %s check ExePath matches existing: [%v]\n",
				baseInfo.PID, phase, baseInfo.ExePath)
		} else if (len(baseInfo.ExePath) > 60) && (len(procInfo.ExePath) > len(baseInfo.ExePath)) {
			// BPF ExePath might be truncated (64 byte limit)
			if strings.HasPrefix(procInfo.ExePath, baseInfo.ExePath[:60]) {
				globalLogger.Trace("process", "PID %d: Replacing truncated ExePath with %s check: [%v] -> [%v]\n",
					baseInfo.PID, phase, baseInfo.ExePath, procInfo.ExePath)
				baseInfo.ExePath = procInfo.ExePath
			} else {
				globalLogger.Trace("process", "PID %d: %s check ExePath doesn't share prefix with current, keeping current: [%v] vs [%v]\n",
					baseInfo.PID, phase, baseInfo.ExePath, procInfo.ExePath)
			}
		} else if phase == "second" {
			// For second phase, prefer /proc data for a more complete picture
			globalLogger.Trace("process", "PID %d: Updating ExePath from second check: [%v] -> [%v]\n",
				baseInfo.PID, baseInfo.ExePath, procInfo.ExePath)
			baseInfo.ExePath = procInfo.ExePath

		} else {
			// For first phase, trust BPF data over /proc
			globalLogger.Trace("process", "PID %d: Keeping BPF ExePath over first check data: [%v] vs [%v]\n",
				baseInfo.PID, baseInfo.ExePath, procInfo.ExePath)
		}
	}

	// Handle CmdLine merging with similar logic
	if procInfo.CmdLine != "" {
		if baseInfo.CmdLine == "" {
			// If we don't have a CmdLine yet, use anything we can get
			globalLogger.Trace("process", "PID %d: Adding CmdLine from %s check: [%v]\n",
				baseInfo.PID, phase, procInfo.CmdLine)
			baseInfo.CmdLine = procInfo.CmdLine

		} else if baseInfo.CmdLine == procInfo.CmdLine {
			// Both are the same, nothing to do
			globalLogger.Trace("process", "PID %d: %s check CmdLine matches existing: [%v]\n",
				baseInfo.PID, phase, baseInfo.CmdLine)
		} else if len(procInfo.CmdLine) > len(baseInfo.CmdLine) {
			// BPF CmdLine is often truncated or incomplete
			if len(baseInfo.CmdLine) > 15 && strings.HasPrefix(procInfo.CmdLine, baseInfo.CmdLine[:15]) {
				globalLogger.Trace("process", "PID %d: Replacing truncated CmdLine with %s check: [%v] -> [%v]\n",
					baseInfo.PID, phase, baseInfo.CmdLine, procInfo.CmdLine)
				baseInfo.CmdLine = procInfo.CmdLine

			} else if strings.Contains(procInfo.CmdLine, baseInfo.CmdLine) {
				globalLogger.Trace("process", "PID %d: Replacing partial CmdLine with %s check: [%v] -> [%v]\n",
					baseInfo.PID, phase, baseInfo.CmdLine, procInfo.CmdLine)
				baseInfo.CmdLine = procInfo.CmdLine

			} else if phase == "second" {
				// For second phase, prefer the longer command line
				globalLogger.Trace("process", "PID %d: Updating CmdLine from second check: [%v] -> [%v]\n",
					baseInfo.PID, baseInfo.CmdLine, procInfo.CmdLine)
				baseInfo.CmdLine = procInfo.CmdLine

			} else {
				globalLogger.Trace("process", "PID %d: %s check CmdLine doesn't share prefix, keeping current: [%v] vs [%v]\n",
					baseInfo.PID, phase, baseInfo.CmdLine, procInfo.CmdLine)
			}
		} else {
			globalLogger.Trace("process", "PID %d: Current CmdLine longer than %s check: [%v] vs [%v]\n",
				baseInfo.PID, phase, baseInfo.CmdLine, procInfo.CmdLine)
		}
	}

	// For other fields, always take from proc if missing, and prefer second proc check
	if baseInfo.WorkingDir == "" || (phase == "second" && procInfo.WorkingDir != "") {
		baseInfo.WorkingDir = procInfo.WorkingDir
	}

	if baseInfo.PPID == 0 && procInfo.PPID > 0 {
		baseInfo.PPID = procInfo.PPID
	}

	if baseInfo.UID == 0 && procInfo.UID > 0 {
		baseInfo.UID = procInfo.UID
	}

	if baseInfo.GID == 0 && procInfo.GID > 0 {
		baseInfo.GID = procInfo.GID
	}

	if len(procInfo.Environment) > 0 && (len(baseInfo.Environment) == 0 || phase == "second") {
		baseInfo.Environment = procInfo.Environment
	}

	if procInfo.ContainerID != "" && (baseInfo.ContainerID == "" || phase == "second") {
		baseInfo.ContainerID = procInfo.ContainerID
	}
}

// Inherit properties from parent for fork events
func InheritFromParent(info, parentInfo *types.ProcessInfo) {
	info.ExePath = parentInfo.ExePath
	info.CmdLine = parentInfo.CmdLine
	info.WorkingDir = parentInfo.WorkingDir
	info.Username = parentInfo.Username
	info.ContainerID = parentInfo.ContainerID
	info.BinaryHash = parentInfo.BinaryHash
	info.Environment = parentInfo.Environment
	info.ParentComm = parentInfo.Comm

	// Use parent's values only if child doesn't have them
	if info.UID == 0 && parentInfo.UID != 0 {
		info.UID = parentInfo.UID
	}
	if info.GID == 0 && parentInfo.GID != 0 {
		info.GID = parentInfo.GID
	}
}

func findAndCacheParentProcess(ppid uint32) *types.ProcessInfo {
	// Check if already in cache
	if info, exists := GetProcessFromCache(ppid); exists {
		return info
	}

	// Special case for PID 2
	if ppid == 2 {
		info := &types.ProcessInfo{
			PID:        2,
			ParentComm: "swapper/0",
			EventType:  "exec",
		}
		CompleteProcessInfo(info, types.ProcessLevelMinimal) // PID 2 special case is handled in CompleteProcessInfo
		AddOrUpdateProcessCache(2, info)
		return info
	}

	// Regular process
	info := CollectProcMetadata(ppid)
	if info != nil && (info.ExePath != "" || info.CmdLine != "") {
		// Explicitly set ParentComm from /proc if available
		if info.ParentComm == "" && info.PPID > 0 {
			parentProcDir := fmt.Sprintf("/proc/%d", info.PPID)
			procReadsTotal.Inc() // os.Stat counts as a /proc read
			if _, err := os.Stat(parentProcDir); err == nil {
				procReadsTotal.Inc() // reading comm file is another /proc read
				if commBytes, err := os.ReadFile(fmt.Sprintf("%s/comm", parentProcDir)); err == nil {
					info.ParentComm = strings.TrimSpace(string(commBytes))
				}
			}
		}

		// Apply standard enrichment and finalization
		CompleteProcessInfo(info, types.ProcessLevelBasic) // Get exe path and cmdline for parent matching
		success := AddOrUpdateProcessCache(ppid, info)
		if !success {
			globalLogger.Debug("cache", "Failed to add PID %d to cache", ppid)
		}
		return info
	}

	return nil
}

// Core process information collection - keep it minimal and fast
func CollectProcMetadata(pid uint32) *types.ProcessInfo {
	info := &types.ProcessInfo{
		PID: pid,
	}

	procDir := fmt.Sprintf("/proc/%d", pid)
	procReadsTotal.Inc()
	if _, err := os.Stat(procDir); os.IsNotExist(err) {
		return info
	}

	procReadsTotal.Inc()
	if commBytes, err := os.ReadFile(fmt.Sprintf("%s/comm", procDir)); err == nil {
		info.Comm = strings.TrimSpace(string(commBytes))
		globalLogger.Trace("process", "PID %d: Read comm from /proc: [%v]\n", pid, info.Comm)
	}

	procReadsTotal.Inc()
	if exePath, err := os.Readlink(fmt.Sprintf("%s/exe", procDir)); err == nil {
		info.ExePath = exePath
	}

	procReadsTotal.Inc()
	if cmdlineBytes, err := os.ReadFile(fmt.Sprintf("%s/cmdline", procDir)); err == nil && len(cmdlineBytes) > 0 {
		args := bytes.Split(cmdlineBytes, []byte{0})
		var cmdArgs []string
		for _, arg := range args {
			if len(arg) > 0 {
				cmdArgs = append(cmdArgs, string(arg))
			}
		}
		if len(cmdArgs) > 0 {
			info.CmdLine = strings.Join(cmdArgs, " ")
		}
	}

	procReadsTotal.Inc()
	if cwd, err := os.Readlink(fmt.Sprintf("%s/cwd", procDir)); err == nil {
		info.WorkingDir = cwd
	}

	// Extract UID/GID/PPID from status
	procReadsTotal.Inc()
	if statusData, err := os.ReadFile(fmt.Sprintf("%s/status", procDir)); err == nil {
		lines := strings.Split(string(statusData), "\n")
		for _, line := range lines {
			if strings.HasPrefix(line, "Uid:") {
				fields := strings.Fields(line)
				if len(fields) > 1 {
					if uid, err := strconv.ParseUint(fields[1], 10, 32); err == nil {
						info.UID = uint32(uid)
					}
				}
			} else if strings.HasPrefix(line, "Gid:") {
				fields := strings.Fields(line)
				if len(fields) > 1 {
					if gid, err := strconv.ParseUint(fields[1], 10, 32); err == nil {
						info.GID = uint32(gid)
					}
				}
			} else if strings.HasPrefix(line, "PPid:") {
				fields := strings.Fields(line)
				if len(fields) > 1 {
					if ppid, err := strconv.ParseUint(fields[1], 10, 32); err == nil {
						info.PPID = uint32(ppid)
					}
				}
			}
		}
	}

	return info
}

// Finalize a process with UIDs and hashes
func FinalizeProcessInfo(info *types.ProcessInfo) {
	// Calculate hash if enabled and not already set
	if globalEngine != nil && globalEngine.config.HashBinaries &&
		info.BinaryHash == "" && info.ExePath != "" && info.ExePath != "[kernel]" {
		if hash, err := CalculateMD5(info.ExePath); err == nil {
			info.BinaryHash = hash
			operationResults.WithLabelValues("process", "hash_calc", "success").Inc()
		} else {
			operationResults.WithLabelValues("process", "hash_calc", "failure").Inc()
		}
	}

	// Set start time if not already set
	if info.StartTime.IsZero() {
		procReadsTotal.Inc()
		if stat, err := os.Stat(fmt.Sprintf("/proc/%d", info.PID)); err == nil {
			info.StartTime = stat.ModTime()
		} else {
			// Use current time as fallback
			info.StartTime = time.Now()
		}
	}

	// Calculate ProcessUID if not already set
	if info.ProcessUID == "" {
		h := fnv.New32a()
		h.Write([]byte(fmt.Sprintf("%s-%d", info.StartTime.Format(time.RFC3339Nano), info.PID)))
		if info.ExePath != "" {
			h.Write([]byte(info.ExePath))
		}
		info.ProcessUID = fmt.Sprintf("%x", h.Sum32())
	}
}

// The main function that takes a process through all stages
func CompleteProcessInfo(info *types.ProcessInfo, level types.ProcessInfoLevel) *types.ProcessInfo {
	levelName := map[types.ProcessInfoLevel]string{
		types.ProcessLevelMinimal: "minimal",
		types.ProcessLevelBasic:   "basic",
		types.ProcessLevelFull:    "full",
	}[level]

	timer := prometheus.NewTimer(processInfoDurations.WithLabelValues(levelName))
	defer timer.ObserveDuration()

	// Special case handling for PID 2 (from EnrichProcessInfo)
	if info.PID == 2 {
		info.Comm = "kthreadd"
		info.ExePath = "[kernel]"
		info.WorkingDir = "/"
		info.Username = "root"
		info.UID = 0
		info.GID = 0
		info.PPID = 0
		info.ParentComm = "swapper/0"
		info.StartTime = BootTime
		FinalizeProcessInfo(info)
		return info
	}

	// Minimal level - always do these since they're cheap
	if info.Username == "" {
		info.Username = GetUsernameFromUID(info.UID)
		processInfoLevelStats.WithLabelValues("minimal", "success").Inc()
	}
	if info.Comm == "" && info.ExePath != "" {
		info.Comm = filepath.Base(info.ExePath)
	}

	if level == types.ProcessLevelMinimal {
		FinalizeProcessInfo(info)
		return info
	}

	// Basic level adds executable info
	if info.ExePath == "" {
		processInfoProcReads.WithLabelValues("basic", "exe").Inc()
		if exePath, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", info.PID)); err == nil {
			info.ExePath = exePath
			processInfoLevelStats.WithLabelValues("basic", "success").Inc()
		} else {
			processInfoLevelStats.WithLabelValues("basic", "failure").Inc()
		}
	}

	if info.CmdLine == "" {
		processInfoProcReads.WithLabelValues("basic", "cmdline").Inc()
		if cmdline, err := readProcFile(info.PID, "cmdline"); err == nil {
			info.CmdLine = cmdline
			processInfoLevelStats.WithLabelValues("basic", "success").Inc()
		} else {
			processInfoLevelStats.WithLabelValues("basic", "failure").Inc()
		}
	}

	if level == types.ProcessLevelBasic {
		FinalizeProcessInfo(info)
		return info
	}

	// Full level - include everything
	processInfoLevelStats.WithLabelValues("full", "start").Inc()

	// Environment variables
	if len(info.Environment) == 0 {
		processInfoProcReads.WithLabelValues("full", "environ").Inc()
		if env, err := getProcessEnvironment(info.PID); err == nil {
			info.Environment = env
		}
	}

	// Container ID detection
	if info.ContainerID == "" {
		processInfoProcReads.WithLabelValues("full", "cgroup").Inc()
		if cgroupData, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", info.PID)); err == nil {
			lines := strings.Split(string(cgroupData), "\n")
			for _, line := range lines {
				if strings.Contains(line, "docker") || strings.Contains(line, "containerd") {
					parts := strings.Split(line, "/")
					for i := len(parts) - 1; i >= 0; i-- {
						part := parts[i]
						if containerIDRegex.MatchString(part) {
							info.ContainerID = part
							break
						}
					}
					if info.ContainerID != "" {
						break
					}
				}
			}
		}
	}

	// Working directory
	if info.WorkingDir == "" {
		processInfoProcReads.WithLabelValues("full", "cwd").Inc()
		if cwd, err := os.Readlink(fmt.Sprintf("/proc/%d/cwd", info.PID)); err == nil {
			info.WorkingDir = cwd
		}
	}

	// Parent process info
	if info.ParentComm == "" && info.PPID > 0 {
		procReadsTotal.Inc()
		parentProcDir := fmt.Sprintf("/proc/%d", info.PPID)
		if _, err := os.Stat(parentProcDir); err == nil {
			if commBytes, err := os.ReadFile(fmt.Sprintf("%s/comm", parentProcDir)); err == nil {
				info.ParentComm = strings.TrimSpace(string(commBytes))
			}
		}
	}

	processInfoLevelStats.WithLabelValues("full", "complete").Inc()
	FinalizeProcessInfo(info)
	return info
}

// readProcFile reads a file from /proc and returns its contents
func readProcFile(pid uint32, filename string) (string, error) {
	procReadsTotal.Inc()
	data, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/%s", pid, filename))
	if err != nil {
		return "", err
	}
	return string(bytes.TrimSpace(data)), nil
}

// getProcessEnvironment reads and parses environment variables
func getProcessEnvironment(pid uint32) ([]string, error) {
	procReadsTotal.Inc()
	data, err := readProcFile(pid, "environ")
	if err != nil {
		return nil, err
	}

	// Split on null bytes
	return strings.Split(data, "\x00"), nil
}

// Add this where your other BPF-related functions are
func LookupCmdline(bpfObjs *execveObjects, pid uint32) (string, error) {
	var cmdLine struct {
		Args [128]byte
	}

	globalLogger.Trace("process", "Attempting to lookup cmdline from BPF map for PID %d\n", pid)

	// Try to lookup in the cmdlines map
	err := bpfObjs.Cmdlines.Lookup(pid, &cmdLine)
	if err != nil {
		globalLogger.Trace("process", "Failed to lookup cmdline from BPF map for PID %d: %v\n", pid, err)
		return "", fmt.Errorf("failed to lookup cmdline: %v", err)
	}

	// Convert to string, handling null bytes
	cmdStr := make([]byte, 0, 128)
	for _, b := range cmdLine.Args {
		if b == 0 {
			break
		}
		cmdStr = append(cmdStr, b)
	}

	if len(cmdStr) > 0 {
		globalLogger.Trace("process", "Successfully got cmdline from BPF map for PID %d: %s\n", pid, string(cmdStr))
	} else {
		globalLogger.Trace("process", "Got empty cmdline from BPF map for PID %d\n", pid)
	}

	return string(cmdStr), nil
}

func shouldIgnoreProcessExit(comm string) bool {
	// Check for direct matches
	if ignoreExitProcesses[comm] {
		return true
	}

	// Check for prefix matches
	for prefix := range ignoreExitProcesses {
		if strings.HasSuffix(prefix, "/") && strings.HasPrefix(comm, prefix) {
			return true
		}
	}

	return false
}

func sanitizeCommandLine(cmdline string) string {
	// Replace newlines with \n and pipes with spaces
	cmdline = strings.ReplaceAll(cmdline, "\n", "\\n")
	cmdline = strings.ReplaceAll(cmdline, "|", " ")
	return cmdline
}

func initializeProcessCache() {
	timer := NewEventTimer("cache_init")
	defer timer.ObserveDuration()

	procReadsTotal.Inc()
	entries, err := os.ReadDir("/proc")
	if err != nil {
		log.Printf("Error reading /proc: %v", err)
		return
	}

	var processCount, cachedCount int
	for _, entry := range entries {
		pid, err := strconv.ParseUint(entry.Name(), 10, 32)
		if err != nil {
			continue
		}
		processCount++

		// Special case for PID 2
		if pid == 2 {
			info := &types.ProcessInfo{
				PID:       2,
				EventType: "exec",
			}
			CompleteProcessInfo(info, types.ProcessLevelFull) // This will handle the special case
			AddOrUpdateProcessCache(2, info)
			cachedCount++
			continue
		}

		// Regular process
		info := CollectProcMetadata(uint32(pid))
		if info != nil && (info.ExePath != "" || info.CmdLine != "") {
			info.EventType = "exec"

			// Apply standard enrichment and finalization
			CompleteProcessInfo(info, types.ProcessLevelFull)
			AddOrUpdateProcessCache(uint32(pid), info)
			cachedCount++
		}
	}

	if globalLogger != nil {
		globalLogger.Debug("process", "Process cache initialization complete: found %d processes, cached %d",
			processCount, cachedCount)
	}
}
