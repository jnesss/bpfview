// output.go
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

	"github.com/jnesss/bpfview/types"
)

// EventFormatter defines the interface for different output formats
type EventFormatter interface {
	Initialize() error
	Close() error

	FormatProcess(event *types.ProcessEvent, info *types.ProcessInfo) error
	FormatNetwork(event *types.NetworkEvent, info *types.ProcessInfo) error
	FormatDNS(event *types.UserSpaceDNSEvent, info *types.ProcessInfo) error
	FormatTLS(event *types.UserSpaceTLSEvent, info *types.ProcessInfo) error
}

// TextFormatter implements the original pipe-delimited format
type TextFormatter struct {
	processLog *os.File
	networkLog *os.File
	dnsLog     *os.File
	tlsLog     *os.File
	envLog     *os.File
	logDir     string
	mu         sync.Mutex
}

func NewTextFormatter(logDir string) (*TextFormatter, error) {
	if logDir == "" {
		return nil, fmt.Errorf("log directory cannot be empty")
	}
	return &TextFormatter{
		logDir: logDir,
	}, nil
}

func (f *TextFormatter) Initialize() error {
	// Create log directory if it doesn't exist
	if err := os.MkdirAll(f.logDir, 0755); err != nil {
		return fmt.Errorf("failed to create log directory: %v", err)
	}

	// Check and rotate existing logs
	if err := f.rotateExistingLogs(); err != nil {
		return fmt.Errorf("failed to rotate logs: %v", err)
	}

	// Open all log files
	var err error
	f.processLog, err = os.OpenFile(
		filepath.Join(f.logDir, "process.log"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		0644,
	)
	if err != nil {
		return fmt.Errorf("failed to open process log: %v", err)
	}

	f.networkLog, err = os.OpenFile(
		filepath.Join(f.logDir, "network.log"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		0644,
	)
	if err != nil {
		f.Close()
		return fmt.Errorf("failed to open network log: %v", err)
	}

	f.dnsLog, err = os.OpenFile(
		filepath.Join(f.logDir, "dns.log"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		0644,
	)
	if err != nil {
		f.Close()
		return fmt.Errorf("failed to open dns log: %v", err)
	}

	f.tlsLog, err = os.OpenFile(
		filepath.Join(f.logDir, "tls.log"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		0644,
	)
	if err != nil {
		f.Close()
		return fmt.Errorf("failed to open tls log: %v", err)
	}

	f.envLog, err = os.OpenFile(
		filepath.Join(f.logDir, "env.log"),
		os.O_CREATE|os.O_APPEND|os.O_WRONLY,
		0644,
	)
	if err != nil {
		f.Close()
		return fmt.Errorf("failed to open environment log: %v", err)
	}

	// Write headers
	f.writeProcessHeader()
	f.writeNetworkHeader()
	f.writeDNSHeader()
	f.writeTLSHeader()
	f.writeEnvHeader()

	return nil
}

func (f *TextFormatter) Close() error {
	if f.processLog != nil {
		f.processLog.Close()
	}
	if f.networkLog != nil {
		f.networkLog.Close()
	}
	if f.dnsLog != nil {
		f.dnsLog.Close()
	}
	if f.tlsLog != nil {
		f.tlsLog.Close()
	}
	if f.envLog != nil {
		f.envLog.Close()
	}
	return nil
}

func (f *TextFormatter) writeProcessHeader() {
	fmt.Fprintln(f.processLog, "timestamp|session_uid|process_uid|event_type|pid|ppid|uid_user|gid|comm|parent_comm|exe_path|binary_hash|cmdline|username|container_id|cwd|start_time|exit_time|exit_code|duration")
}

func (f *TextFormatter) writeNetworkHeader() {
	fmt.Fprintln(f.networkLog, "timestamp|session_uid|process_uid|network_uid|pid|comm|ppid|parent_comm|protocol|src_ip|src_port|dst_ip|dst_port|direction|bytes")
}

func (f *TextFormatter) writeDNSHeader() {
	fmt.Fprintln(f.dnsLog, "timestamp|session_uid|process_uid|network_uid|dns_conversation_uid|pid|comm|ppid|parent_comm|event_type|dns_flags|query|type|txid|src_ip|src_port|dst_ip|dst_port|answers|ttl")
}

func (f *TextFormatter) writeTLSHeader() {
	fmt.Fprintln(f.tlsLog, "timestamp|session_uid|process_uid|network_uid|pid|comm|ppid|parent_comm|src_ip|src_port|dst_ip|dst_port|version|sni|cipher_suites|supported_groups|handshake_length|ja4|ja4_hash")
}

func (f *TextFormatter) writeEnvHeader() {
	fmt.Fprintln(f.envLog, "timestamp|sessionid|process_uid|uid|pid|comm|env_var")
}

func (f *TextFormatter) FormatProcess(event *types.ProcessEvent, info *types.ProcessInfo) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	event_timestamp := BpfTimestampToTime(event.Timestamp)
	event_timeStr := event_timestamp.Format(time.RFC3339Nano)

	h := fnv.New32a()
	start_timeStr := info.StartTime.Format(time.RFC3339Nano)
	h.Write([]byte(fmt.Sprintf("%s-%d", start_timeStr, info.PID)))
	if info.ExePath != "" {
		h.Write([]byte(info.ExePath))
	}
	eventUID := fmt.Sprintf("%x", h.Sum32())

	eventType := "EXEC"
	if event.EventType == types.EVENT_PROCESS_EXIT {
		eventType = "EXIT"
	}

	// Clean fields (reusing existing cleanField functions)
	comm := cleanField(info.Comm, "-")
	parentComm := cleanField(string(bytes.TrimRight(event.ParentComm[:], "\x00")), "-")
	exePath := cleanField(info.ExePath, "-")
	cmdline := cleanField(info.CmdLine, "-")
	username := cleanField(info.Username, "-")
	containerID := cleanField(info.ContainerID, "-")
	cwd := cleanField(info.WorkingDir, "-")

	// Format timestamps
	startTimeStr := formatTimeField(info.StartTime)
	exitTimeStr := formatTimeField(info.ExitTime)

	// Calculate duration
	duration := "-"
	if eventType == "EXIT" &&
		!info.StartTime.IsZero() && info.StartTime.Year() >= 2000 &&
		!info.ExitTime.IsZero() && info.ExitTime.Year() >= 2000 {
		duration = info.ExitTime.Sub(info.StartTime).String()
	}

	exitcode := "-"
	if eventType == "EXIT" {
		exitcode = fmt.Sprint(info.ExitCode)
	}

	binaryHash := cleanField(info.BinaryHash, "-")

	_, err := fmt.Fprintf(f.processLog, "%s|%s|%s|%s|%d|%d|%d|%d|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s|%s\n",
		event_timeStr,    // Event timestamp
		globalSessionUid, // Session identifier
		eventUID,         // Enhanced UID
		eventType,        // EXEC or EXIT
		info.PID,
		info.PPID,
		info.UID,
		info.GID,
		comm,         // Process name
		parentComm,   // Parent process name
		exePath,      // Full executable path
		binaryHash,   // Binary MD5 hash
		cmdline,      // Command line with arguments
		username,     // Username
		containerID,  // Container ID if available
		cwd,          // Current Working Directory
		startTimeStr, // Start time
		exitTimeStr,  // Exit time
		exitcode,     // Exit code
		duration,     // Process duration
	)
	if err != nil {
		return fmt.Errorf("failed to write process log: %v", err)
	}

	// Handle environment variables if present
	if len(info.Environment) > 0 {
		return f.formatEnvironment(event, info)
	}

	return nil
}

// Helper functions - we'll need to move these from logging.go or reimplement them
func cleanField(value string, defaultValue string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return defaultValue
	}
	return value
}

func formatTimeField(t time.Time) string {
	if !t.IsZero() && t.Year() >= 2000 {
		return t.Format(time.RFC3339Nano)
	}
	return "-"
}

func (f *TextFormatter) FormatNetwork(event *types.NetworkEvent, info *types.ProcessInfo) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	timestamp := BpfTimestampToTime(event.Timestamp)
	uid := generateConnID(event.Pid, event.Ppid,
		uint32ToNetIP(event.SrcIP),
		uint32ToNetIP(event.DstIP),
		event.SrcPort, event.DstPort)

	comm := string(bytes.TrimRight(event.Comm[:], "\x00"))
	parentComm := string(bytes.TrimRight(event.ParentComm[:], "\x00"))

	direction := ">"
	if event.Direction == types.FLOW_INGRESS {
		direction = "<"
	}

	// Calculate process_uid for correlation
	h := fnv.New32a()
	process_start_str := info.StartTime.Format(time.RFC3339Nano)
	h.Write([]byte(fmt.Sprintf("%s-%d", process_start_str, event.Pid)))
	if info.ExePath != "" {
		h.Write([]byte(info.ExePath))
	}
	processUID := fmt.Sprintf("%x", h.Sum32())

	_, err := fmt.Fprintf(f.networkLog, "%s|%s|%s|%s|%d|%s|%d|%s|%s|%s|%d|%s|%d|%s|%d\n",
		timestamp.Format(time.RFC3339Nano),
		globalSessionUid,
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

	return err
}

func (f *TextFormatter) FormatDNS(event *types.UserSpaceDNSEvent, info *types.ProcessInfo) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	timestamp := BpfTimestampToTime(event.Timestamp)
	network_uid := generateConnID(event.Pid, event.Ppid, event.SourceIP, event.DestIP, event.SourcePort, event.DestPort)

	eventType := "QUERY"
	if event.IsResponse {
		eventType = "RESPONSE"
	}

	// Calculate process_uid for correlation
	h := fnv.New32a()
	process_start_str := info.StartTime.Format(time.RFC3339Nano)
	h.Write([]byte(fmt.Sprintf("%s-%d", process_start_str, event.Pid)))
	if info.ExePath != "" {
		h.Write([]byte(info.ExePath))
	}
	processUID := fmt.Sprintf("%x", h.Sum32())

	if !event.IsResponse {
		// For queries, log the questions
		for _, q := range event.Questions {
			_, err := fmt.Fprintf(f.dnsLog, "%s|%s|%s|%s|%s|%d|%s|%d|%s|%s|0x%04x|%s|%s|0x%04x|%s|%d|%s|%d|-|-\n",
				timestamp.Format(time.RFC3339Nano),
				globalSessionUid,
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
			if err != nil {
				return err
			}
		}
	} else {
		// For responses, log only the answers
		for _, a := range event.Answers {
			answer := formatDNSAnswer(&a)
			_, err := fmt.Fprintf(f.dnsLog, "%s|%s|%s|%s|%s|%d|%s|%d|%s|%s|0x%04x|%s|%s|0x%04x|%s|%d|%s|%d|%s|%d\n",
				timestamp.Format(time.RFC3339Nano),
				globalSessionUid,
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
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func (f *TextFormatter) FormatTLS(event *types.UserSpaceTLSEvent, info *types.ProcessInfo) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	timestamp := BpfTimestampToTime(event.Timestamp)
	network_uid := generateConnID(event.Pid, event.Ppid, event.SourceIP, event.DestIP, event.SourcePort, event.DestPort)

	// Calculate process_uid for correlation
	h := fnv.New32a()
	process_start_str := info.StartTime.Format(time.RFC3339Nano)
	h.Write([]byte(fmt.Sprintf("%s-%d", process_start_str, event.Pid)))
	if info.ExePath != "" {
		h.Write([]byte(info.ExePath))
	}
	processUID := fmt.Sprintf("%x", h.Sum32())

	// Format cipher suites
	cipherSuites := formatCipherSuites(event.CipherSuites)
	supportedGroups := formatSupportedGroups(event.SupportedGroups)

	ja4 := "-"
	if event.JA4 != "" {
		ja4 = event.JA4
	}

	ja4hash := "-"
	if event.JA4Hash != "" {
		ja4hash = event.JA4Hash
	}

	_, err := fmt.Fprintf(f.tlsLog, "%s|%s|%s|%s|%d|%s|%d|%s|%s|%d|%s|%d|%s|%s|%s|%s|%d|%s|%s\n",
		timestamp.Format(time.RFC3339Nano),
		globalSessionUid,
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
		cipherSuites,
		supportedGroups,
		event.HandshakeLength,
		ja4,
		ja4hash)

	return err
}

func (f *TextFormatter) formatEnvironment(event *types.ProcessEvent, info *types.ProcessInfo) error {
	if len(info.Environment) == 0 {
		return nil
	}

	timestamp := BpfTimestampToTime(event.Timestamp)
	timeStr := timestamp.Format(time.RFC3339Nano)

	// Generate unique ID (same as process event)
	h := fnv.New32a()
	h.Write([]byte(fmt.Sprintf("%s-%d", timeStr, info.PID)))
	if info.ExePath != "" {
		h.Write([]byte(info.ExePath))
	}
	eventUID := fmt.Sprintf("%x", h.Sum32())

	comm := cleanField(info.Comm, "-")

	// Log each non-empty environment variable
	for _, env := range info.Environment {
		if strings.TrimSpace(env) == "" {
			continue
		}

		_, err := fmt.Fprintf(f.envLog, "%s|%s|%d|%s|%s\n",
			timeStr,
			eventUID,
			info.PID,
			comm,
			env,
		)
		if err != nil {
			return err
		}
	}

	return nil
}

func (f *TextFormatter) rotateExistingLogs() error {
	// First check if process.log exists and get its timestamp and session_uid
	processLogPath := filepath.Join(f.logDir, "process.log")
	if _, err := os.Stat(processLogPath); os.IsNotExist(err) {
		return nil // No logs exist yet
	}

	timestamp, sessionUID := extractTimestampAndSessionUID(processLogPath)
	if timestamp == "" {
		// Fallback to current time if we can't extract
		timestamp = time.Now().Format("2006-01-02-15-04-05")
	}
	if sessionUID == "" {
		sessionUID = "unknown"
	}

	// Log types to check and rotate
	logTypes := []string{"process", "network", "dns", "tls", "env"}

	for _, logType := range logTypes {
		currentLogPath := filepath.Join(f.logDir, logType+".log")

		// Check if log exists
		if _, err := os.Stat(currentLogPath); os.IsNotExist(err) {
			continue // Log doesn't exist, nothing to rotate
		}

		// Create archived name including session_uid
		archivedPath := filepath.Join(f.logDir, fmt.Sprintf("%s.%s.%s.log", logType, timestamp, sessionUID))

		// Rename file
		os.Rename(currentLogPath, archivedPath)
	}
	return nil
}

func extractTimestampAndSessionUID(logPath string) (timestamp, sessionUID string) {
	file, err := os.Open(logPath)
	if err != nil {
		return "", ""
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)

	// Skip header
	if !scanner.Scan() {
		return "", ""
	}

	// Read first event line
	if !scanner.Scan() {
		return "", ""
	}

	line := scanner.Text()
	parts := strings.Split(line, "|")
	if len(parts) < 2 {
		return "", ""
	}

	// Parse timestamp from first field
	t, err := time.Parse(time.RFC3339Nano, parts[0])
	if err != nil {
		return "", ""
	}

	// Get session_uid from second field
	sessionUID = parts[1]

	// Format timestamp for filename
	timestamp = t.Format("2006-01-02-15-04-05")

	return timestamp, sessionUID
}

func formatDNSAnswer(answer *types.DNSAnswer) string {
	switch answer.Type {
	case 1, 28: // A or AAAA
		if answer.IPAddress != nil {
			return answer.IPAddress.String()
		}
	case 5: // CNAME
		return answer.CName
	}
	return fmt.Sprintf("%s record", dnsTypeToString(answer.Type))
}

func formatCipherSuites(cipherSuites []uint16) string {
	if len(cipherSuites) == 0 {
		return "-"
	}
	strs := make([]string, len(cipherSuites))
	for i, cs := range cipherSuites {
		strs[i] = fmt.Sprintf("0x%04x", cs)
	}
	return strings.Join(strs, ",")
}

func formatSupportedGroups(groups []uint16) string {
	if len(groups) == 0 {
		return "-"
	}
	strs := make([]string, len(groups))
	for i, g := range groups {
		strs[i] = formatSupportedGroup(g)
	}
	return strings.Join(strs, ",")
}
