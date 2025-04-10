package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type ProcessInfo struct {
	PID         uint32
	PPID        uint32
	Comm        string
	ExePath     string
	CmdLine     string
	WorkingDir  string
	Environment []string
	UID         uint32
	GID         uint32
	Username    string
	ContainerID string
	StartTime   time.Time
	ExitTime    time.Time
	ExitCode    uint32
	BinaryHash  string
}

// Process cache to maintain state between EXEC and EXIT events
var (
	processCache     = make(map[uint32]*ProcessInfo)
	processCacheLock sync.RWMutex
)

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

func handleProcessEvent(event *ProcessEvent, bpfObjs *execveObjects) {
	if event.EventType == EVENT_PROCESS_EXEC {
		handleProcessExecEvent(event, bpfObjs)
	} else if event.EventType == EVENT_PROCESS_EXIT {
		handleProcessExitEvent(event)
	}
}

func handleProcessExitEvent(event *ProcessEvent) {
	// Check if we should ignore this exit
	comm := string(bytes.TrimRight(event.Comm[:], "\x00"))
	if shouldIgnoreProcessExit(comm) {
		return
	}

	// Try to update exit time in the cache
	exitTime := BpfTimestampToTime(event.Timestamp)
	if !UpdateProcessExitTime(event.Pid, exitTime) {
		// Either the process doesn't exist in cache or already has exit time
		// Sometimes we get multiple EXIT messages from BPF so this is normal, not an error
		return
	}

	// Debug log for event details
	globalLogger.Debug("process", "Processing EXEC event for PID %d\n", event.Pid)
	globalLogger.Debug("process", "BPF data - Comm: %s, UID: %d, GID: %d\n",
		string(bytes.TrimRight(event.Comm[:], "\x00")),
		event.Uid,
		event.Gid)

	info := &ProcessInfo{
		PID:      event.Pid,
		Comm:     comm,
		UID:      event.Uid,
		GID:      event.Gid,
		ExitCode: event.ExitCode,
		ExitTime: exitTime,
	}

	if cachedInfo, exists := GetProcessFromCache(event.Pid); exists {
		// Copy start time for duration calculation and UID
		info.StartTime = cachedInfo.StartTime

		// Copy other fields for matching purposes (not logging these but still need to match)
		info.ExePath = cachedInfo.ExePath
		info.CmdLine = cachedInfo.CmdLine
		info.WorkingDir = cachedInfo.WorkingDir
		info.Username = cachedInfo.Username
		info.ContainerID = cachedInfo.ContainerID
		info.PPID = cachedInfo.PPID
	}

	// Filter check AFTER enrichment and cache updates, but BEFORE logging
	if globalEngine != nil && !globalEngine.ShouldLog(info) {
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

	// Log to file with proper structured format if logger is available
	if globalLogger != nil {
		globalLogger.LogProcess(event, info)
	}

	// Remove process from cache one second later after processing EXIT
	//  This delay preserves the cache for a process exec that might come out of order
	time.Sleep(1 * time.Second)

	processCacheLock.Lock()
	delete(processCache, event.Pid)
	processCacheLock.Unlock()
}

func handleProcessExecEvent(event *ProcessEvent, bpfObjs *execveObjects) {
	// Debug log for event details
	globalLogger.Debug("process", "Processing EXEC event for PID %d\n", event.Pid)

	// Log raw BPF data
	globalLogger.Debug("process", "BPF data - Comm: %s, Parent: %s, UID: %d, GID: %d\n",
		string(bytes.TrimRight(event.Comm[:], "\x00")),
		string(bytes.TrimRight(event.ParentComm[:], "\x00")),
		event.Uid,
		event.Gid)

	// try to get cmdline from BPF map first
	var kernelCmdLine string
	if bpfObjs != nil {
		if cmdline, err := LookupCmdline(bpfObjs, event.Pid); err == nil {
			globalLogger.Debug("process", "Phase 1 - Got cmdline from BPF for PID %d: %s\n", event.Pid, cmdline)
			kernelCmdLine = cmdline
		} else {
			globalLogger.Debug("process", "Phase 1 - Failed to get cmdline from BPF for PID %d: %v\n", event.Pid, err)
		}
	}

	// Enrich the process event with additional information and save to the cache
	enrichedInfo := EnrichProcessEvent(event, kernelCmdLine) // Pass the cmdline we already looked up
	AddOrUpdateProcessCache(event.Pid, enrichedInfo)

	if globalEngine != nil {
		globalEngine.processTree.AddProcess(enrichedInfo)
	}

	// Filter check AFTER enrichment and cache updates, but BEFORE logging
	if globalEngine != nil && !globalEngine.ShouldLog(enrichedInfo) {
		return
	}

	// Log to console with enhanced information
	parentComm := string(bytes.TrimRight(event.ParentComm[:], "\x00"))

	// Build the message using strings.Builder
	var msg strings.Builder
	fmt.Fprintf(&msg, "EXEC: PID=%d comm=%s\n", enrichedInfo.PID, enrichedInfo.Comm)
	fmt.Fprintf(&msg, "      Parent: [%d] %s\n", enrichedInfo.PPID, parentComm)
	fmt.Fprintf(&msg, "      User: %s (%d/%d)\n", enrichedInfo.Username, enrichedInfo.UID, enrichedInfo.GID)
	fmt.Fprintf(&msg, "      Path: %s", enrichedInfo.ExePath)
	if enrichedInfo.WorkingDir != "" {
		fmt.Fprintf(&msg, "\n      CWD: %s", enrichedInfo.WorkingDir)
	}
	if enrichedInfo.CmdLine != "" {
		fmt.Fprintf(&msg, "\n      Command: %s", sanitizeCommandLine(enrichedInfo.CmdLine))
	}
	if enrichedInfo.ContainerID != "" && enrichedInfo.ContainerID != "-" {
		fmt.Fprintf(&msg, "\n      Container: %s", enrichedInfo.ContainerID)
	}

	globalLogger.Info("process", "%s", msg.String())

	// Log to file with proper structured format if logger is available
	if globalLogger != nil {
		globalLogger.LogProcess(event, enrichedInfo)
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
func AddOrUpdateProcessCache(pid uint32, info *ProcessInfo) {
	processCacheLock.Lock()
	defer processCacheLock.Unlock()

	processCache[pid] = info
}

// GetProcessFromCache retrieves process info from the cache
func GetProcessFromCache(pid uint32) (*ProcessInfo, bool) {
	processCacheLock.RLock()
	defer processCacheLock.RUnlock()

	info, exists := processCache[pid]
	return info, exists
}

// UpdateProcessExitTime updates only the exit time for a process in the cache
func UpdateProcessExitTime(pid uint32, exitTime time.Time) bool {
	processCacheLock.Lock()
	defer processCacheLock.Unlock()

	info, exists := processCache[pid]
	if !exists {
		return false
	}

	// Only update if we haven't recorded an exit time yet
	if !info.ExitTime.IsZero() {
		return false // Already has exit time
	}

	info.ExitTime = exitTime
	processCache[pid] = info
	return true
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

// CollectProcMetadata gathers information about a process from /proc
func CollectProcMetadata(pid uint32) *ProcessInfo {
	info := &ProcessInfo{
		PID: pid,
	}

	procDir := fmt.Sprintf("/proc/%d", pid)

	// Check if process still exists
	if _, err := os.Stat(procDir); os.IsNotExist(err) {
		globalLogger.Debug("process", "PID %d - /proc entry doesn't exist\n", pid)
		return info
	}

	// Get executable path
	if exePath, err := os.Readlink(fmt.Sprintf("%s/exe", procDir)); err == nil {
		globalLogger.Debug("process", "PID %d - Got exe path from /proc: %s\n", pid, exePath)
		info.ExePath = exePath
	} else {
		globalLogger.Debug("process", "PID %d - Failed to read exe path from /proc: %v\n", pid, err)
	}

	// Get command line with proper null-byte handling
	if cmdlineBytes, err := os.ReadFile(fmt.Sprintf("%s/cmdline", procDir)); err == nil && len(cmdlineBytes) > 0 {
		if len(cmdlineBytes) == 0 {
			globalLogger.Debug("process", "PID %d - /proc cmdline file was empty\n", pid)
		} else if cmdlineBytes[0] == 0 {
			globalLogger.Debug("process", "PID %d - /proc cmdline starts with null byte\n", pid)
		} else {

			args := bytes.Split(cmdlineBytes, []byte{0})
			var cmdArgs []string
			for _, arg := range args {
				if len(arg) > 0 {
					cmdArgs = append(cmdArgs, string(arg))
				}
			}
			if len(cmdArgs) > 0 {
				info.CmdLine = strings.Join(cmdArgs, " ")
				globalLogger.Debug("process", "PID %d - Got cmdline from /proc: %s\n", pid, info.CmdLine)
			}
		}
	} else {
		globalLogger.Debug("process", "PID %d - Failed to read cmdline from /proc: %v\n", pid, err)
	}

	// Get initial working directory
	if cwd, err := os.Readlink(fmt.Sprintf("%s/cwd", procDir)); err == nil {
		globalLogger.Debug("process", "PID %d - Got working dir from /proc: %s\n", pid, cwd)
		info.WorkingDir = cwd
	} else {
		globalLogger.Debug("process", "PID %d - Failed to read working dir from /proc: %v\n", pid, err)
	}

	// Get environment variables
	if env, err := getProcessEnvironment(pid); err == nil {
		globalLogger.Debug("process", "PID %d - Successfully read %d environment variables\n", pid, len(env))
		info.Environment = env
	} else {
		globalLogger.Debug("process", "PID %d - Failed to read environment: %v\n", pid, err)
	}

	// Check for container ID
	if info.ContainerID == "" {
		if cgroupData, err := os.ReadFile(fmt.Sprintf("%s/cgroup", procDir)); err == nil {
			lines := strings.Split(string(cgroupData), "\n")
			for _, line := range lines {
				if strings.Contains(line, "docker") || strings.Contains(line, "containerd") {
					parts := strings.Split(line, "/")
					for i := len(parts) - 1; i >= 0; i-- {
						part := parts[i]
						if containerIDRegex.MatchString(part) {
							globalLogger.Debug("process", "PID %d - Found container ID: %s\n", pid, part)
							info.ContainerID = part
							break
						}
					}
					if info.ContainerID != "" {
						break
					}
				}
			}
		} else {
			globalLogger.Debug("process", "PID %d - Failed to read cgroup info: %v\n", pid, err)
		}
	}

	return info
}

// readProcFile reads a file from /proc and returns its contents
func readProcFile(pid uint32, filename string) (string, error) {
	data, err := ioutil.ReadFile(fmt.Sprintf("/proc/%d/%s", pid, filename))
	if err != nil {
		return "", err
	}
	return string(bytes.TrimSpace(data)), nil
}

// getProcessEnvironment reads and parses environment variables
func getProcessEnvironment(pid uint32) ([]string, error) {
	data, err := readProcFile(pid, "environ")
	if err != nil {
		return nil, err
	}

	// Split on null bytes
	return strings.Split(data, "\x00"), nil
}

// EnrichProcessEvent adds additional information to a process event from /proc
func EnrichProcessEvent(event *ProcessEvent, kernelCmdLine string) *ProcessInfo {
	pid := event.Pid

	// Get the basics from the kernel event
	//  This is the master ProcessInfo we are going to return
	//  We merge values from kernel mode BPF and two separate usermode /proc lookups
	info := &ProcessInfo{
		PID:      pid,
		PPID:     event.Ppid,
		Comm:     string(bytes.TrimRight(event.Comm[:], "\x00")),
		UID:      event.Uid,
		GID:      event.Gid,
		ExitCode: event.ExitCode,
	}

	if event.EventType == EVENT_PROCESS_EXIT {
		// For EXIT events, set the exit time using the event timestamp from kernelmode and return immediately
		info.ExitTime = BpfTimestampToTime(event.Timestamp)
		return info

	} else if event.EventType == EVENT_PROCESS_EXEC {
		// For EXEC events, set the start time using the event timestamp from kernelmode
		info.StartTime = BpfTimestampToTime(event.Timestamp)

		// Use the kernel cmdline we already looked up if available
		if kernelCmdLine != "" {
			info.CmdLine = kernelCmdLine
		}

		// Get executable path from kernel data if available
		var kernelExePath string
		if len(event.ExePath) > 0 {
			kernelExePath = string(bytes.TrimRight(event.ExePath[:], "\x00"))
			if kernelExePath != "" {
				info.ExePath = kernelExePath
			}
		}

		// Get parent process command
		if len(event.ParentComm) > 0 {
			parentComm := string(bytes.TrimRight(event.ParentComm[:], "\x00"))
			if parentComm != "" {
				// Could store in the ProcessInfo if needed
			}
		}

		info.Username = GetUsernameFromUID(info.UID)

		globalLogger.Debug("process", "%d: BPF kernel data: [%v] [%v]\n", pid, info.CmdLine, info.ExePath)

		// Phase 2: First proc check

		firstProcInfo := CollectProcMetadata(pid)

		var exe_path_match, cmd_line_match bool
		if firstProcInfo.ExePath != "" {
			if info.ExePath == "" {
				// anything is better than nothing
				info.ExePath = firstProcInfo.ExePath
				globalLogger.Debug("process", "%d: Replacing blank BPF ExePath with /proc ExePath: [%v]\n", pid, info.ExePath)
			} else if info.ExePath == firstProcInfo.ExePath {
				globalLogger.Debug("process", "%d: BPF and /proc ExePath both same: [%v]\n", pid, info.ExePath)
				exe_path_match = true
			} else if (len(info.ExePath) > 60) && (len(firstProcInfo.ExePath) > len(info.ExePath)) {
				// BPF ExePath is max 64 bytes so it could get truncated
				// Dont even consider /proc exepath unless there's a chance BPF exepath was truncated
				if strings.HasPrefix(firstProcInfo.ExePath, info.ExePath[:60]) {
					globalLogger.Debug("process", "%d: Replacing truncated BPF ExePath with /proc ExePath: [%v] [%v]\n", pid, info.ExePath, firstProcInfo.ExePath)
					info.ExePath = firstProcInfo.ExePath
				} else {
					globalLogger.Debug("process", "%d: BPF ExePath does not share common prefix with /proc ExePath, trusting BPF: [%v] [%v]\n", pid, info.ExePath, firstProcInfo.ExePath)
				}
			} else {
				globalLogger.Debug("process", "%d: Trusting BPF ExePath over /proc ExePath: [%v] [%v]\n", pid, info.ExePath, firstProcInfo.ExePath)
			}
		}

		if firstProcInfo.CmdLine != "" {
			if info.CmdLine == "" {
				// anything is better than nothing
				info.CmdLine = firstProcInfo.CmdLine
				globalLogger.Debug("process", "%d: Replacing BLANK BPF CmdLine with /proc CmdLine: [%v]\n", pid, info.CmdLine)
			} else if info.CmdLine == firstProcInfo.CmdLine {
				globalLogger.Debug("process", "%d: BPF and /proc CmdLine both same: [%v]\n", pid, info.CmdLine)
				cmd_line_match = true
			} else if len(firstProcInfo.CmdLine) > len(info.CmdLine) {
				// BPF CmdLine is VERY limited and each arg could be truncated
				if len(info.CmdLine) > 15 && strings.HasPrefix(firstProcInfo.CmdLine, info.CmdLine[:15]) {
					// example:
					// DEBUG 2 2835509: Replacing truncated BPF CmdLine with /proc CmdLine: [curl -s --max-time] [curl -s --max-time 5 -H X-aws-ec2-metadata-token:AQAEAAN_7UhbnrPmG1anTPFbytQG7zQEe171jxkYvdZsVrw8CrT3cQ== -f http://169.254.169.254/latest/meta-data/mac]
					globalLogger.Debug("process", "%d: Replacing truncated BPF CmdLine with /proc CmdLine: [%v] [%v]\n", pid, info.CmdLine, firstProcInfo.CmdLine)
					info.CmdLine = firstProcInfo.CmdLine
				} else if strings.Contains(firstProcInfo.CmdLine, info.CmdLine) {
					// example:
					// DEBUG 2 2835803: Replacing partial BPF CmdLine with /proc CmdLine: [/usr/bin/setup-policy-routes ens5 refresh] [/usr/bin/bash /usr/bin/setup-policy-routes ens5 refresh]

					globalLogger.Debug("process", "%d: Replacing partial BPF CmdLine with /proc CmdLine: [%v] [%v]\n", pid, info.CmdLine, firstProcInfo.CmdLine)
					info.CmdLine = firstProcInfo.CmdLine
				} else {
					globalLogger.Debug("process", "%d: BPF CmdLine does not share common prefix with /proc CmdLine, trusting BPF: [%v] [%v]\n", pid, info.CmdLine, firstProcInfo.CmdLine)
				}
			} else {
				globalLogger.Debug("process", "%d: BPF CmdLine is longer than /proc CmdLine: [%v] [%v]\n", pid, info.CmdLine, firstProcInfo.CmdLine)
			}
		}

		// these values only come from /proc metadata, not from kernel mode BPF so take whatever first proc gives us
		info.WorkingDir = firstProcInfo.WorkingDir
		info.Environment = firstProcInfo.Environment
		info.ContainerID = firstProcInfo.ContainerID

		// Wait briefly for exec to complete
		time.Sleep(2 * time.Millisecond)

		// Second collection after exec should be complete
		secondProcInfo := CollectProcMetadata(pid)

		if secondProcInfo.ExePath != "" {
			if info.ExePath == secondProcInfo.ExePath || exe_path_match {
				// ignore
			} else if info.ExePath != kernelExePath {
				// trust secondProcInfo ExePath more than firstProcInfo
				globalLogger.Debug("process", "%d: Replacing first /proc ExePath: [%v] [%v]\n", pid, info.ExePath, secondProcInfo.ExePath)
				info.ExePath = secondProcInfo.ExePath
			} else if (len(info.ExePath) > 60) && (len(secondProcInfo.ExePath) > len(info.ExePath)) {
				// BPF ExePath might have been truncated..
				globalLogger.Debug("process", "%d: Replacing BPF ExePath: [%v] [%v]\n", pid, info.ExePath, secondProcInfo.ExePath)
				info.ExePath = secondProcInfo.ExePath
			} else {
				// otherwise, use existing BPF exepath
			}
		}

		if secondProcInfo.CmdLine != "" {
			if info.CmdLine == secondProcInfo.CmdLine || cmd_line_match {
				// ignore
			} else {
				// for now, lets try trusting the later /proc command line and evaluate
				// example:
				// DEBUG 3 2835418: Replacing CmdLine: [/usr/bin/sed -r -e] [/usr/bin/sed -r -e s/^[[:blank:]]*([[:upper:]_]+)=([[:print:][:digit:]\._-]+|"[[:print:][:digit:]\._-]+")/export \1=\2/;t;d /etc/locale.conf]
				globalLogger.Debug("process", "%d: Replacing CmdLine: [%v] [%v]\n", pid, info.CmdLine, secondProcInfo.CmdLine)
				info.CmdLine = secondProcInfo.CmdLine
			}
		}

		// use secondProcInfo if it exists for the other values
		//  no debug prints because its less interesting
		if secondProcInfo.WorkingDir != "" {
			info.WorkingDir = secondProcInfo.WorkingDir
		}
		if len(secondProcInfo.Environment) > 0 {
			info.Environment = secondProcInfo.Environment
		}
		if len(secondProcInfo.ContainerID) > 0 {
			info.ContainerID = secondProcInfo.ContainerID
		}

		// Get absolute path for ExePath if it's not already absolute
		if info.ExePath != "" && !filepath.IsAbs(info.ExePath) {
			if info.WorkingDir != "" {
				info.ExePath = filepath.Join(info.WorkingDir, info.ExePath)
			} else {
				// Try to resolve through PATH
				if path, err := exec.LookPath(info.ExePath); err == nil {
					info.ExePath = path
				}
			}
		}

		if info.ExePath != "" {
			info.Comm = filepath.Base(info.ExePath)
		}

		globalLogger.Debug("process", "config: %v exe %v", globalEngine.config, info.ExePath)
		// If hash binaries is enabled and we have an executable path, calculate hash
		if globalEngine != nil && globalEngine.config.HashBinaries &&
			info.ExePath != "" {
			// Only calculate hash for EXEC events (not EXIT)
			if event.EventType == EVENT_PROCESS_EXEC {
				if hash, err := CalculateMD5(info.ExePath); err == nil {
					info.BinaryHash = hash
					globalLogger.Debug("process", "Calculated MD5 hash for %s: %s\n",
						info.ExePath, info.BinaryHash)
				} else {
					globalLogger.Debug("process", "Failed to calculate MD5 hash for %s: %v\n",
						info.ExePath, err)
				}
			}
		}
	}

	return info
}

// Add this where your other BPF-related functions are
func LookupCmdline(bpfObjs *execveObjects, pid uint32) (string, error) {
	var cmdLine struct {
		Args [128]byte
	}

	globalLogger.Debug("process", "Attempting to lookup cmdline from BPF map for PID %d\n", pid)

	// Try to lookup in the cmdlines map
	err := bpfObjs.Cmdlines.Lookup(pid, &cmdLine)
	if err != nil {
		globalLogger.Debug("process", "Failed to lookup cmdline from BPF map for PID %d: %v\n", pid, err)
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
		globalLogger.Debug("process", "Successfully got cmdline from BPF map for PID %d: %s\n", pid, string(cmdStr))
	} else {
		globalLogger.Debug("process", "Got empty cmdline from BPF map for PID %d\n", pid)
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

		info := CollectProcMetadata(uint32(pid))
		if info != nil && info.ExePath != "" {
			// Set Comm from ExePath basename, just like in EnrichProcessEvent
			info.Comm = filepath.Base(info.ExePath)
			AddOrUpdateProcessCache(uint32(pid), info)
			cachedCount++
			if globalLogger != nil {
				globalLogger.Debug("process", "Cached PID %d: %s (%s)", pid, info.Comm, info.ExePath)
			}
		}
	}

	if globalLogger != nil {
		globalLogger.Debug("process", "Process cache initialization complete: found %d processes, cached %d",
			processCount, cachedCount)
	}
}
