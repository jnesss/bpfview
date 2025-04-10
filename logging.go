package main

import (
	"bufio"
	"bytes"
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type LogLevel int

const (
	LogLevelError LogLevel = iota
	LogLevelWarning
	LogLevelInfo
	LogLevelDebug
	LogLevelTrace
)

type Logger struct {
	processLog *os.File
	networkLog *os.File
	dnsLog     *os.File
	tlsLog     *os.File
	envLog     *os.File
	lock       sync.Mutex

	consoleLevel  LogLevel
	fileLevel     LogLevel
	showTimestamp bool
	logDir        string
}

func NewLogger(logDir string, consoleLevel, fileLevel LogLevel, showTimestamp bool) (*Logger, error) {
	// Create log directory if it doesn't exist
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create log directory: %v", err)
	}

	logger := &Logger{
		consoleLevel:  consoleLevel,
		fileLevel:     fileLevel,
		showTimestamp: showTimestamp,
		logDir:        logDir,
	}

	// Check and rotate existing logs
	rotateExistingLogs(logDir)

	// Open fresh log files
	var err error
	logger.processLog, err = os.OpenFile(
		filepath.Join(logDir, "process.log"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		0644,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to open process log: %v", err)
	}

	logger.networkLog, err = os.OpenFile(
		filepath.Join(logDir, "network.log"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		0644,
	)
	if err != nil {
		logger.Close()
		return nil, fmt.Errorf("failed to open network log: %v", err)
	}

	logger.dnsLog, err = os.OpenFile(
		filepath.Join(logDir, "dns.log"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		0644,
	)
	if err != nil {
		logger.Close()
		return nil, fmt.Errorf("failed to open dns log: %v", err)
	}

	logger.tlsLog, err = os.OpenFile(
		filepath.Join(logDir, "tls.log"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		0644,
	)
	if err != nil {
		logger.Close()
		return nil, fmt.Errorf("failed to open tls log: %v", err)
	}

	logger.envLog, err = os.OpenFile(
		filepath.Join(logDir, "env.log"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		0644,
	)
	if err != nil {
		logger.Close()
		return nil, fmt.Errorf("failed to open environment log: %v", err)
	}

	// Write headers
	logger.writeProcessHeader()
	logger.writeNetworkHeader()
	logger.writeDNSHeader()
	logger.writeTLSHeader()
	logger.writeEnvHeader()

	return logger, nil
}

func rotateExistingLogs(logDir string) {
	// Log types to check and rotate
	logTypes := []string{"process", "network", "dns", "tls", "env"}

	for _, logType := range logTypes {
		currentLogPath := filepath.Join(logDir, logType+".log")

		// Check if log exists
		if _, err := os.Stat(currentLogPath); os.IsNotExist(err) {
			continue // Log doesn't exist, nothing to rotate
		}

		// Try to extract timestamp from first log entry
		timestamp := extractTimestampFromLog(currentLogPath)
		if timestamp == "" {
			// Fallback to current time if we can't extract
			timestamp = time.Now().Format("2006-01-02-15-04-05")
		}

		// Create archived name
		archivedPath := filepath.Join(logDir, fmt.Sprintf("%s.%s.log", logType, timestamp))

		// Rename file
		os.Rename(currentLogPath, archivedPath)
	}
}

func extractTimestampFromLog(logPath string) string {
	file, err := os.Open(logPath)
	if err != nil {
		return ""
	}
	defer file.Close()

	// Read first two lines (header + first event)
	scanner := bufio.NewScanner(file)

	// Skip header
	if !scanner.Scan() {
		return ""
	}

	// Read first event line
	if !scanner.Scan() {
		return ""
	}

	line := scanner.Text()
	parts := strings.Split(line, "|")
	if len(parts) < 1 {
		return ""
	}

	// Parse timestamp from first field
	t, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return ""
	}

	// Format for filename
	return t.Format("2006-01-02-15-04-05")
}

func (l *Logger) Close() {
	if l.processLog != nil {
		l.processLog.Close()
	}
	if l.networkLog != nil {
		l.networkLog.Close()
	}
	if l.dnsLog != nil {
		l.dnsLog.Close()
	}
	if l.tlsLog != nil {
		l.tlsLog.Close()
	}
	if l.envLog != nil {
		l.envLog.Close()
	}
}

func (l *Logger) Error(component string, format string, args ...interface{}) {
	l.log(LogLevelError, component, format, args...)
}

func (l *Logger) Warning(component string, format string, args ...interface{}) {
	l.log(LogLevelWarning, component, format, args...)
}

func (l *Logger) Info(component string, format string, args ...interface{}) {
	l.log(LogLevelInfo, component, format, args...)
}

func (l *Logger) Debug(component string, format string, args ...interface{}) {
	l.log(LogLevelDebug, component, format, args...)
}

func (l *Logger) Trace(component string, format string, args ...interface{}) {
	l.log(LogLevelTrace, component, format, args...)
}

func (l *Logger) log(level LogLevel, component string, format string, args ...interface{}) {
	message := fmt.Sprintf(format, args...)

	// Lock for thread safety
	l.lock.Lock()
	defer l.lock.Unlock()

	// Console output if level is sufficient
	if level <= l.consoleLevel {
		prefix := ""
		if l.showTimestamp {
			prefix = time.Now().Format("2006-01-02 15:04:05.000") + " "
		}

		levelStr := [...]string{"ERROR", "WARNING", "INFO", "DEBUG", "TRACE"}[level]
		fmt.Printf("%s[%s][%s] %s\n", prefix, levelStr, component, message)
	}

	// add logging to write to a central log file here
}

func (l *Logger) writeProcessHeader() {
	fmt.Fprintln(l.processLog, "timestamp|session_uid|process_uid|event_type|pid|ppid|uid_user|gid|comm|parent_comm|exe_path|binary_hash|cmdline|username|container_id|cwd|start_time|exit_time|exit_code|duration")
}

func (l *Logger) writeNetworkHeader() {
	fmt.Fprintln(l.networkLog, "timestamp|session_uid|process_uid|network_uid|pid|comm|ppid|parent_comm|protocol|src_ip|src_port|dst_ip|dst_port|direction|bytes")
}

func (l *Logger) writeDNSHeader() {
	fmt.Fprintln(l.dnsLog, "timestamp|session_uid|process_uid|network_uid|dns_conversation_uid|pid|comm|ppid|parent_comm|event_type|dns_flags|query|type|txid|src_ip|src_port|dst_ip|dst_port|answers|ttl")
}

func (l *Logger) writeTLSHeader() {
	fmt.Fprintln(l.tlsLog, "timestamp|session_uid|process_uid|network_uid|pid|comm|ppid|parent_comm|src_ip|src_port|dst_ip|dst_port|version|sni|cipher_suites|supported_groups|handshake_length|ja4|ja4_hash")
}

func (l *Logger) writeEnvHeader() {
	fmt.Fprintln(l.envLog, "timestamp|sessionid|process_uid|uid|pid|comm|env_var")
}

func (l *Logger) LogProcess(event *ProcessEvent, enrichedInfo *ProcessInfo) {
	l.lock.Lock()
	defer l.lock.Unlock()

	event_timestamp := BpfTimestampToTime(event.Timestamp)
	event_timeStr := event_timestamp.Format(time.RFC3339Nano)

	// Generate unique ID
	h := fnv.New32a()
	start_timeStr := enrichedInfo.StartTime.Format(time.RFC3339Nano)
	h.Write([]byte(fmt.Sprintf("%s-%d", start_timeStr, enrichedInfo.PID)))
	if enrichedInfo.ExePath != "" {
		h.Write([]byte(enrichedInfo.ExePath))
	}
	eventUID := fmt.Sprintf("%x", h.Sum32())

	eventType := "EXEC"
	if event.EventType == EVENT_PROCESS_EXIT {
		eventType = "EXIT"
	}

	// Clean up fields
	comm := strings.TrimSpace(enrichedInfo.Comm)
	if comm == "" {
		comm = "-"
	}

	parentComm := strings.TrimSpace(string(bytes.TrimRight(event.ParentComm[:], "\x00")))
	if parentComm == "" || event.EventType == EVENT_PROCESS_EXIT {
		parentComm = "-"
	}

	exePath := strings.TrimSpace(enrichedInfo.ExePath)
	if exePath == "" || event.EventType == EVENT_PROCESS_EXIT {
		exePath = "-"
	}

	cmdline := strings.TrimSpace(enrichedInfo.CmdLine)
	if cmdline == "" || event.EventType == EVENT_PROCESS_EXIT {
		cmdline = "-"
	} else {
		cmdline = sanitizeCommandLine(cmdline)
	}

	username := strings.TrimSpace(enrichedInfo.Username)
	if username == "" || event.EventType == EVENT_PROCESS_EXIT {
		username = "-"
	}

	containerID := strings.TrimSpace(enrichedInfo.ContainerID)
	if containerID == "" {
		containerID = "-"
	}

	cwd := strings.TrimSpace(enrichedInfo.WorkingDir)
	if cwd == "" || event.EventType == EVENT_PROCESS_EXIT {
		cwd = "-"
	}

	// Use the already converted StartTime and ExitTime from enrichedInfo
	// These should have been properly set in EnrichProcessEvent
	startTimeStr := "-"
	if !enrichedInfo.StartTime.IsZero() && enrichedInfo.StartTime.Year() >= 2000 {
		startTimeStr = enrichedInfo.StartTime.Format(time.RFC3339Nano)
	}

	exitTimeStr := "-"
	if !enrichedInfo.ExitTime.IsZero() && enrichedInfo.ExitTime.Year() >= 2000 {
		exitTimeStr = enrichedInfo.ExitTime.Format(time.RFC3339Nano)
	}

	// Calculate duration only if both times are valid
	duration := "-"
	if eventType == "EXIT" &&
		!enrichedInfo.StartTime.IsZero() && enrichedInfo.StartTime.Year() >= 2000 &&
		!enrichedInfo.ExitTime.IsZero() && enrichedInfo.ExitTime.Year() >= 2000 {
		duration = enrichedInfo.ExitTime.Sub(enrichedInfo.StartTime).String()
	}

	exitcode := "-"
	if eventType == "EXIT" {
		exitcode = fmt.Sprint(enrichedInfo.ExitCode)
	}

	// Add binary hash field
	binaryHash := "-"
	if enrichedInfo.BinaryHash != "" {
		binaryHash = enrichedInfo.BinaryHash
	}

	// Write the log entry
	fmt.Fprintf(l.processLog, "%s|%s|%s|%s|%d|%d|%d|%d|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n",
		event_timeStr,    // Event timestamp
		globalSessionUid, // 8 character string identifying this session for correlation
		eventUID,         // Enhanced UID
		eventType,        // EXEC or EXIT
		enrichedInfo.PID,
		enrichedInfo.PPID,
		enrichedInfo.UID,
		enrichedInfo.GID,
		comm,         // Process name
		parentComm,   // Parent process name
		exePath,      // Full executable path
		binaryHash,   // Binary MD5 hash
		cmdline,      // Command line with arguments
		username,     // Username
		containerID,  // Container ID if available
		cwd,          // Current Working Directory
		startTimeStr, // Start time (from enrichedInfo)
		exitTimeStr,  // Exit time (from enrichedInfo)
		exitcode,     // Exit code
		duration,     // Process duration
	)
}

func (l *Logger) LogNetwork(event *NetworkEvent, processinfo *ProcessInfo) {
	l.lock.Lock()
	defer l.lock.Unlock()

	timestamp := BpfTimestampToTime(event.Timestamp)
	uid := generateConnID(event.Pid, event.Ppid,
		uint32ToNetIP(event.SrcIP),
		uint32ToNetIP(event.DstIP),
		event.SrcPort, event.DstPort)

	comm := string(bytes.TrimRight(event.Comm[:], "\x00"))
	parentComm := string(bytes.TrimRight(event.ParentComm[:], "\x00"))

	direction := ">"
	if event.Direction == FLOW_INGRESS {
		direction = "<"
	}

	// Calculate process_uid for correlation
	h := fnv.New32a()
	process_start_str := processinfo.StartTime.Format(time.RFC3339Nano)
	h.Write([]byte(fmt.Sprintf("%s-%d", process_start_str, event.Pid)))
	if processinfo.ExePath != "" {
		h.Write([]byte(processinfo.ExePath))
	}
	processUID := fmt.Sprintf("%x", h.Sum32())

	fmt.Fprintf(l.networkLog, "%s|%s|%s|%s|%d|%s|%d|%s|%s|%s|%d|%s|%d|%s|%d\n",
		timestamp.Format(time.RFC3339Nano),
		globalSessionUid, // 8 character string identifying this session for correlation
		processUID,
		uid,
		event.Pid,
		comm,
		event.Ppid,
		parentComm,
		protocolToString(event.Protocol),
		ipToString(event.SrcIP),
		event.SrcPort,
		ipToString(event.DstIP),
		event.DstPort,
		direction,
		event.BytesCount,
	)
}

func (l *Logger) LogDNS(event *UserSpaceDNSEvent, processinfo *ProcessInfo) {
	l.lock.Lock()
	defer l.lock.Unlock()

	timestamp := BpfTimestampToTime(event.Timestamp)
	network_uid := generateConnID(event.Pid, event.Ppid, event.SourceIP, event.DestIP, event.SourcePort, event.DestPort)

	eventType := "QUERY"
	if event.IsResponse {
		eventType = "RESPONSE"
	}

	// Calculate process_uid for correlation
	h := fnv.New32a()
	process_start_str := processinfo.StartTime.Format(time.RFC3339Nano)
	h.Write([]byte(fmt.Sprintf("%s-%d", process_start_str, event.Pid)))
	if processinfo.ExePath != "" {
		h.Write([]byte(processinfo.ExePath))
	}
	processUID := fmt.Sprintf("%x", h.Sum32())

	// For each question, create a log entry
	for _, q := range event.Questions {
		fmt.Fprintf(l.dnsLog, "%s|%s|%s|%s|%s|%d|%s|%d|%s|%s|0x%04x|%s|%s|0x%04x|%s|%d|%s|%d|-|-\n",
			timestamp.Format(time.RFC3339Nano),
			globalSessionUid, // 8 character string identifying this session for correlation
			processUID,
			network_uid,
			event.ConversationID,
			event.Pid,
			event.Comm,
			event.Ppid,
			event.ParentComm,
			eventType,
			event.DNSFlags,
			q.Name,
			dnsTypeToString(q.Type),
			event.TransactionID,
			event.SourceIP.String(),
			event.SourcePort,
			event.DestIP.String(),
			event.DestPort,
		)
	}

	// For responses, also log the answers
	if event.IsResponse {
		for _, a := range event.Answers {
			var answer string
			switch a.Type {
			case 1, 28: // A or AAAA
				if a.IPAddress != nil {
					answer = a.IPAddress.String()
				}
			case 5: // CNAME
				answer = a.CName
			default:
				answer = fmt.Sprintf("%s record", dnsTypeToString(a.Type))
			}

			fmt.Fprintf(l.dnsLog, "%s|%s|%s|%s|%s|%d|%s|%d|%s|%s|0x%04x|%s|%s|0x%04x|%s|%d|%s|%d|%s|%d\n",
				timestamp.Format(time.RFC3339Nano),
				globalSessionUid, // 8 character string identifying this session for correlation
				processUID,
				network_uid,
				event.ConversationID,
				event.Pid,
				event.Comm,
				event.Ppid,
				event.ParentComm,
				eventType,
				event.DNSFlags,
				a.Name,
				dnsTypeToString(a.Type),
				event.TransactionID,
				event.SourceIP.String(),
				event.SourcePort,
				event.DestIP.String(),
				event.DestPort,
				answer,
				a.TTL,
			)
		}
	}
}

func (l *Logger) LogTLS(event *UserSpaceTLSEvent, processinfo *ProcessInfo) {
	l.lock.Lock()
	defer l.lock.Unlock()

	timestamp := BpfTimestampToTime(event.Timestamp)
	network_uid := generateConnID(event.Pid, event.Ppid, event.SourceIP, event.DestIP, event.SourcePort, event.DestPort)

	// Calculate process_uid for correlation
	h := fnv.New32a()
	process_start_str := processinfo.StartTime.Format(time.RFC3339Nano)
	h.Write([]byte(fmt.Sprintf("%s-%d", process_start_str, event.Pid)))
	if processinfo.ExePath != "" {
		h.Write([]byte(processinfo.ExePath))
	}
	processUID := fmt.Sprintf("%x", h.Sum32())

	// Format cipher suites
	cipherSuites := make([]string, len(event.CipherSuites))
	for i, cs := range event.CipherSuites {
		cipherSuites[i] = fmt.Sprintf("0x%04x", cs)
	}

	// Format supported groups
	supportedGroups := make([]string, len(event.SupportedGroups))
	for i, g := range event.SupportedGroups {
		supportedGroups[i] = formatSupportedGroup(g)
	}

	ja4 := "-"
	if event.JA4 != "" {
		ja4 = event.JA4
	}

	ja4hash := "-"
	if event.JA4Hash != "" {
		ja4hash = event.JA4Hash
	}

	// 	fmt.Fprintln(l.tlsLog, "timestamp|session_uid|process_uid|network_uid|pid|comm|ppid|parent_comm|src_ip|src_port|dst_ip|dst_port|version|sni|cipher_suites|supported_groups|handshake_length|ja4|ja4_hash")

	fmt.Fprintf(l.tlsLog, "%s|%s|%s|%s|%d|%s|%d|%s|%s|%d|%s|%d|%s|%s|%s|%s|%d|%s|%s\n",
		timestamp.Format(time.RFC3339Nano),
		globalSessionUid, // 8 character string identifying this session for correlation
		processUID,
		network_uid,
		event.Pid,
		event.Comm,
		event.Ppid,
		event.ParentComm,
		event.SourceIP.String(),
		event.SourcePort,
		event.DestIP.String(),
		event.DestPort,
		formatTlsVersion(event.TLSVersion),
		event.SNI,
		strings.Join(cipherSuites, ","),
		strings.Join(supportedGroups, ","),
		event.HandshakeLength,
		ja4,
		ja4hash)
}

func (l *Logger) LogEnvironment(event *ProcessEvent, enrichedInfo *ProcessInfo) {
	if len(enrichedInfo.Environment) == 0 {
		return // No environment variables to log
	}

	l.lock.Lock()
	defer l.lock.Unlock()

	// Use the event timestamp
	timestamp := BpfTimestampToTime(event.Timestamp)
	timeStr := timestamp.Format(time.RFC3339Nano)

	// Generate unique ID (same as process event)
	h := fnv.New32a()
	h.Write([]byte(fmt.Sprintf("%s-%d", timeStr, enrichedInfo.PID)))
	if enrichedInfo.ExePath != "" {
		h.Write([]byte(enrichedInfo.ExePath))
	}
	eventUID := fmt.Sprintf("%x", h.Sum32())

	// Get command name
	comm := strings.TrimSpace(enrichedInfo.Comm)
	if comm == "" {
		comm = "-"
	}

	// Log each non-empty environment variable
	for _, env := range enrichedInfo.Environment {
		// Skip blank environment variables
		if strings.TrimSpace(env) == "" {
			continue
		}

		fmt.Fprintf(l.envLog, "%s|%s|%d|%s|%s\n",
			timeStr,          // Timestamp
			eventUID,         // Event UID (same as process event)
			enrichedInfo.PID, // Process ID
			comm,             // Command name
			env,              // Environment variable
		)
	}
}
