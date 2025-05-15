// gelf.go
package outputformats

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/jnesss/bpfview/types"
)

// GELFFormatter implements the EventFormatter interface for GELF format
// GELF spec: https://go2docs.graylog.org/5-0/getting_started/sending_data.html
type GELFFormatter struct {
	encoder      *json.Encoder
	output       io.Writer
	hostname     string
	hostIP       string
	sessionUID   string
	sigmaEnabled bool
}

// Base GELF message structure - required fields
type gelfMessage struct {
	Version      string  `json:"version"`       // GELF spec version - should be 1.1
	Host         string  `json:"host"`          // Source of the message
	ShortMessage string  `json:"short_message"` // Brief message
	Timestamp    float64 `json:"timestamp"`     // Unix timestamp
	Level        int     `json:"level"`         // Syslog level (info=6)
	FullMessage  string  `json:"full_message,omitempty"`

	// Add Sigma detection fields (all custom fields must be prefixed with _)
	RuleID          string   `json:"_rule_id"`
	RuleName        string   `json:"_rule_name"`
	RuleLevel       string   `json:"_rule_level"`
	RuleDescription string   `json:"_rule_description"`
	MatchDetails    string   `json:"_match_details"`
	RuleReferences  []string `json:"_rule_references"`
	RuleTags        []string `json:"_rule_tags"`

	// All custom fields must be prefixed with _
	TimestampHuman string `json:"_timestamp_human"`
	EventType      string `json:"_event_type"`     // Specific: process_exec, network_flow, etc.
	EventCategory  string `json:"_event_category"` // General: process, network
	SessionUID     string `json:"_session_uid"`
	ProcessUID     string `json:"_process_uid,omitempty"`
	Fingerprint    string `json:"_process_fingerprint,omitempty"`
	NetworkUID     string `json:"_network_uid,omitempty"`
	ConversationID string `json:"_conversation_id,omitempty"`
	CommunityID    string `json:"_community_id,omitempty"`

	// Process-specific fields
	ProcessID       int32  `json:"_process_id"`
	ProcessName     string `json:"_process_name"`
	ParentID        int32  `json:"_parent_id,omitempty"`
	ParentName      string `json:"_parent_name,omitempty"`
	ExePath         string `json:"_exe_path,omitempty"`
	CmdLine         string `json:"_cmdline,omitempty"`
	UserID          int32  `json:"_user_id,omitempty"`
	Username        string `json:"_username,omitempty"`
	GroupID         int32  `json:"_group_id,omitempty"`
	WorkingDir      string `json:"_working_dir,omitempty"`
	ContainerID     string `json:"_container_id,omitempty"`
	ExitCode        uint32 `json:"_exit_code,omitempty"`
	ProcessDuration string `json:"_process_duration,omitempty"`
	BinaryHash      string `json:"_binary_hash,omitempty"`

	// Package information for process
	PackageName     string `json:"_package_name,omitempty"`
	PackageVersion  string `json:"_package_version,omitempty"`
	PackageManager  string `json:"_package_manager,omitempty"`
	IsFromPackage   bool   `json:"_is_from_package,omitempty"`
	PackageVerified bool   `json:"_package_verified,omitempty"`

	// Network-specific fields
	Protocol             string `json:"_protocol,omitempty"`
	SourceIP             string `json:"_source_ip,omitempty"`
	SourcePort           int    `json:"_source_port,omitempty"`
	DestIP               string `json:"_dest_ip,omitempty"`
	DestPort             int    `json:"_dest_port,omitempty"`
	Direction            string `json:"_direction,omitempty"`
	DirectionDescription string `json:"_direction_description,omitempty"`
	ByteCount            int    `json:"_byte_count,omitempty"`

	// TCP flags
	TCPFlags    string `json:"_tcp_flags,omitempty"`
	TCPFlagsRaw uint8  `json:"_tcp_flags_raw,omitempty"`
	TCPFlagFIN  bool   `json:"_tcp_flag_fin,omitempty"`
	TCPFlagSYN  bool   `json:"_tcp_flag_syn,omitempty"`
	TCPFlagRST  bool   `json:"_tcp_flag_rst,omitempty"`
	TCPFlagPSH  bool   `json:"_tcp_flag_psh,omitempty"`
	TCPFlagACK  bool   `json:"_tcp_flag_ack,omitempty"`
	TCPFlagURG  bool   `json:"_tcp_flag_urg,omitempty"`
	TCPFlagECE  bool   `json:"_tcp_flag_ece,omitempty"`
	TCPFlagCWR  bool   `json:"_tcp_flag_cwr,omitempty"`

	// DNS-specific fields
	DNSType        string   `json:"_dns_type,omitempty"`
	DNSFlags       int      `json:"_dns_flags,omitempty"`
	DNSQuestions   []string `json:"_dns_questions,omitempty"`
	DNSAnswers     []string `json:"_dns_answers,omitempty"`
	DNSQueryTypes  []string `json:"_dns_query_types,omitempty"`
	DNSAnswerTypes []string `json:"_dns_answer_types,omitempty"`

	// TLS-specific fields
	TLSVersion      string   `json:"_tls_version,omitempty"`
	TLSSNI          string   `json:"_tls_sni,omitempty"`
	TLSCipherSuites []string `json:"_tls_cipher_suites,omitempty"`
	TLSJa4          string   `json:"_tls_ja4,omitempty"`
	TLSJa4Hash      string   `json:"_tls_ja4_hash,omitempty"`

	// Binary-specific fields (all custom fields must have _ prefix)
	BinaryPath      string `json:"_binary_path,omitempty"`
	BinaryMd5       string `json:"_binary_md5,omitempty"`
	BinarySha256    string `json:"_binary_sha256,omitempty"`
	BinarySize      int64  `json:"_binary_size,omitempty"`
	BinaryFirstSeen string `json:"_binary_first_seen,omitempty"`
	BinaryModTime   string `json:"_binary_mod_time,omitempty"`

	// ELF-specific fields
	BinaryIsElf             bool   `json:"_binary_is_elf,omitempty"`
	BinaryElfType           string `json:"_binary_elf_type,omitempty"`
	BinaryArchitecture      string `json:"_binary_architecture,omitempty"`
	BinaryInterpreter       string `json:"_binary_interpreter,omitempty"`
	BinaryImportCount       int    `json:"_binary_import_count,omitempty"`
	BinaryExportCount       int    `json:"_binary_export_count,omitempty"`
	BinaryStaticallyLinked  bool   `json:"_binary_statically_linked,omitempty"`
	BinaryHasDebugInfo      bool   `json:"_binary_has_debug_info,omitempty"`
	BinaryImportedLibraries string `json:"_binary_imported_libraries,omitempty"` // JSON-encoded

	// Package information for new binary message
	BinaryFromPackage     bool   `json:"_binary_from_package,omitempty"`
	BinaryPackageName     string `json:"_binary_package_name,omitempty"`
	BinaryPackageVersion  string `json:"_binary_package_version,omitempty"`
	BinaryPackageVerified bool   `json:"_binary_package_verified,omitempty"`
	BinaryPackageManager  string `json:"_binary_package_manager,omitempty"`
}

func NewGELFFormatter(output io.Writer, hostname, hostIP, sessionUID string, enableSigma bool) *GELFFormatter {
	f := &GELFFormatter{
		output:       output,
		encoder:      json.NewEncoder(output),
		hostname:     hostname,
		hostIP:       hostIP,
		sessionUID:   sessionUID,
		sigmaEnabled: enableSigma,
	}
	f.encoder.SetEscapeHTML(false)
	return f
}

func (f *GELFFormatter) Initialize() error {
	return nil
}

func (f *GELFFormatter) Close() error {
	return nil
}

func (f *GELFFormatter) FormatProcess(event *types.ProcessEvent, info *types.ProcessInfo, parentinfo *types.ProcessInfo) error {
	// Create base GELF message
	msg := gelfMessage{
		Version:        "1.1",
		Host:           f.getHostname(),
		Level:          6, // Info level
		Timestamp:      float64(BpfTimestampToTime(event.Timestamp).Unix()) + float64(BpfTimestampToTime(event.Timestamp).Nanosecond())/1000000000,
		TimestampHuman: BpfTimestampToTime(event.Timestamp).UTC().Format(time.RFC3339Nano),
		EventCategory:  "process",
		ProcessUID:     info.ProcessUID,
	}

	if info.Fingerprint != "" {
		if info.ParentFingerprint != "" {
			msg.Fingerprint = fmt.Sprintf("%v_%v", info.Fingerprint, info.ParentFingerprint)
		} else {
			msg.Fingerprint = info.Fingerprint
		}
	}

	// Set session info
	msg.SessionUID = f.sessionUID

	// Event type specific details
	var eventType string
	if event.EventType == types.EVENT_PROCESS_EXIT {
		eventType = "process_exit"
		// Set exit code
		msg.ExitCode = info.ExitCode

		// Calculate and set duration if both start and exit times are available
		if !info.StartTime.IsZero() && !info.ExitTime.IsZero() {
			duration := info.ExitTime.Sub(info.StartTime)
			msg.ProcessDuration = duration.String()
		}
	} else if event.EventType == types.EVENT_PROCESS_EXEC {
		eventType = "process_exec"
	} else if event.EventType == types.EVENT_PROCESS_FORK {
		eventType = "process_fork"
	}

	// Process details
	msg.EventType = eventType
	msg.ProcessID = int32(info.PID)
	msg.ProcessName = info.Comm
	msg.ParentID = int32(info.PPID)
	msg.ParentName = string(bytes.TrimRight(event.ParentComm[:], "\x00"))
	msg.ExePath = info.ExePath
	msg.CmdLine = info.CmdLine
	msg.UserID = int32(info.UID)
	msg.Username = info.Username
	msg.GroupID = int32(info.GID)
	msg.WorkingDir = info.WorkingDir
	msg.ContainerID = info.ContainerID
	msg.BinaryHash = info.BinaryHash

	if info.PackageName != "" || info.IsFromPackage {
		msg.PackageName = info.PackageName
		msg.PackageVersion = info.PackageVersion
		msg.PackageManager = info.PackageManager
		msg.IsFromPackage = info.IsFromPackage
		msg.PackageVerified = info.PackageVerified
	}

	msg.ShortMessage = fmt.Sprintf("%s: %s (PID: %d)", eventType, msg.ProcessName, msg.ProcessID)

	var fullMsg strings.Builder
	fullMsg.WriteString(msg.ShortMessage)
	fullMsg.WriteString("\n\n")
	fullMsg.WriteString(fmt.Sprintf("Process Details:\n"))
	fullMsg.WriteString(fmt.Sprintf("Executable: %s\n", info.ExePath))
	if info.CmdLine != "" {
		fullMsg.WriteString(fmt.Sprintf("Command: %s\n", info.CmdLine))
	}
	fullMsg.WriteString(fmt.Sprintf("Working Directory: %s\n", info.WorkingDir))
	fullMsg.WriteString(fmt.Sprintf("User: %s (UID: %d)\n", info.Username, info.UID))
	fullMsg.WriteString(fmt.Sprintf("Group ID: %d\n", info.GID))
	if info.ContainerID != "" && info.ContainerID != "-" {
		fullMsg.WriteString(fmt.Sprintf("Container ID: %s\n", info.ContainerID))
	}
	if info.BinaryHash != "" {
		fullMsg.WriteString(fmt.Sprintf("Binary Hash: %s\n", info.BinaryHash))
	}
	msg.FullMessage = fullMsg.String()

	return f.encoder.Encode(msg)
}

func (f *GELFFormatter) FormatNetwork(event *types.NetworkEvent, info *types.ProcessInfo) error {
	msg := gelfMessage{
		Version:        "1.1",
		Host:           f.getHostname(),
		Level:          6,
		Timestamp:      float64(BpfTimestampToTime(event.Timestamp).Unix()) + float64(BpfTimestampToTime(event.Timestamp).Nanosecond())/1000000000,
		TimestampHuman: BpfTimestampToTime(event.Timestamp).UTC().Format(time.RFC3339Nano),
		EventCategory:  "network",
		EventType:      "network_flow",
		ProcessUID:     info.ProcessUID,
	}

	// Generate correlation IDs
	msg.SessionUID = f.sessionUID
	msg.NetworkUID = GenerateBidirectionalConnID(event.Pid, event.Ppid,
		uint32ToNetIP(event.SrcIP),
		uint32ToNetIP(event.DstIP),
		event.SrcPort, event.DstPort)
	msg.CommunityID = GenerateCommunityID(
		uint32ToNetIP(event.SrcIP),
		uint32ToNetIP(event.DstIP),
		event.SrcPort,
		event.DstPort,
		event.Protocol,
		0) // default seed

	// Basic process info
	msg.ProcessID = int32(event.Pid)
	msg.ProcessName = string(bytes.TrimRight(event.Comm[:], "\x00"))
	msg.ParentID = int32(event.Ppid)
	msg.ParentName = string(bytes.TrimRight(event.ParentComm[:], "\x00"))

	// Network specific fields
	msg.Protocol = protocolToString(event.Protocol)
	msg.SourceIP = ipToString(event.SrcIP)
	msg.SourcePort = int(event.SrcPort)
	msg.DestIP = ipToString(event.DstIP)
	msg.DestPort = int(event.DstPort)
	msg.ByteCount = int(event.BytesCount)

	// Set TCP flags for TCP connections
	if event.Protocol == 6 { // TCP
		msg.TCPFlags = FormatTCPFlags(event.TCPFlags)
		msg.TCPFlagsRaw = event.TCPFlags

		// Individual flags for easier filtering in Graylog
		if (event.TCPFlags & 0x01) != 0 {
			msg.TCPFlagFIN = true
		}
		if (event.TCPFlags & 0x02) != 0 {
			msg.TCPFlagSYN = true
		}
		if (event.TCPFlags & 0x04) != 0 {
			msg.TCPFlagRST = true
		}
		if (event.TCPFlags & 0x08) != 0 {
			msg.TCPFlagPSH = true
		}
		if (event.TCPFlags & 0x10) != 0 {
			msg.TCPFlagACK = true
		}
		if (event.TCPFlags & 0x20) != 0 {
			msg.TCPFlagURG = true
		}
		if (event.TCPFlags & 0x40) != 0 {
			msg.TCPFlagECE = true
		}
		if (event.TCPFlags & 0x80) != 0 {
			msg.TCPFlagCWR = true
		}
	}

	if event.Direction == types.FLOW_INGRESS {
		msg.Direction = "ingress"
		msg.DirectionDescription = "Incoming traffic from external host"
	} else {
		msg.Direction = "egress"
		msg.DirectionDescription = "Outgoing traffic to external service"
	}

	// Set short message
	msg.ShortMessage = fmt.Sprintf("Network connection: %s:%d → %s:%d (%s)",
		msg.SourceIP, msg.SourcePort,
		msg.DestIP, msg.DestPort,
		msg.Protocol)

	var fullMsg strings.Builder
	fullMsg.WriteString(msg.ShortMessage)
	fullMsg.WriteString("\n\n")
	fullMsg.WriteString(fmt.Sprintf("Connection Details:\n"))
	fullMsg.WriteString(fmt.Sprintf("Protocol: %s\n", msg.Protocol))
	fullMsg.WriteString(fmt.Sprintf("Direction: %s (%s)\n", msg.Direction, msg.DirectionDescription))
	fullMsg.WriteString(fmt.Sprintf("Bytes: %d\n", msg.ByteCount))
	if event.Protocol == 6 && event.TCPFlags != 0 {
		fullMsg.WriteString(fmt.Sprintf("TCP Flags: %s\n", msg.TCPFlags))
	}
	fullMsg.WriteString(fmt.Sprintf("\nProcess Details:\n"))
	fullMsg.WriteString(fmt.Sprintf("Process: %s (PID: %d)\n", msg.ProcessName, msg.ProcessID))
	fullMsg.WriteString(fmt.Sprintf("Parent: %s (PPID: %d)\n", msg.ParentName, msg.ParentID))
	msg.FullMessage = fullMsg.String()

	return f.encoder.Encode(msg)
}

func (f *GELFFormatter) FormatDNS(event *types.UserSpaceDNSEvent, info *types.ProcessInfo) error {
	msg := gelfMessage{
		Version:        "1.1",
		Host:           f.getHostname(),
		Level:          6,
		Timestamp:      float64(BpfTimestampToTime(event.Timestamp).Unix()) + float64(BpfTimestampToTime(event.Timestamp).Nanosecond())/1000000000,
		TimestampHuman: BpfTimestampToTime(event.Timestamp).UTC().Format(time.RFC3339Nano),
		EventCategory:  "network",
		ProcessUID:     info.ProcessUID,
	}

	// Generate correlation IDs
	msg.SessionUID = f.sessionUID
	msg.NetworkUID = GenerateBidirectionalConnID(event.Pid, event.Ppid,
		event.SourceIP, event.DestIP,
		event.SourcePort, event.DestPort)
	msg.ConversationID = event.ConversationID
	msg.CommunityID = GenerateCommunityID(
		event.SourceIP,
		event.DestIP,
		event.SourcePort,
		event.DestPort,
		17, // UDP
		0)  // default seed

	// Process info
	msg.ProcessID = int32(event.Pid)
	msg.ProcessName = event.Comm
	msg.ParentID = int32(event.Ppid)
	msg.ParentName = event.ParentComm

	// Network info
	msg.SourceIP = event.SourceIP.String()
	msg.SourcePort = int(event.SourcePort)
	msg.DestIP = event.DestIP.String()
	msg.DestPort = int(event.DestPort)

	// DNS specific fields
	msg.DNSType = "query"
	msg.EventType = "dns_query"
	if event.IsResponse {
		msg.EventType = "dns_response"
		msg.DNSType = "response"
	}
	msg.DNSFlags = int(event.DNSFlags)

	// Collect questions and answers
	for _, q := range event.Questions {
		msg.DNSQuestions = append(msg.DNSQuestions, q.Name)
		msg.DNSQueryTypes = append(msg.DNSQueryTypes, dnsTypeToString(q.Type))
	}

	if event.IsResponse {
		for _, a := range event.Answers {
			switch a.Type {
			case 1, 28: // A or AAAA
				if a.IPAddress != nil {
					msg.DNSAnswers = append(msg.DNSAnswers, a.IPAddress.String())
				}
			case 5: // CNAME
				msg.DNSAnswers = append(msg.DNSAnswers, a.CName)
			default:
				msg.DNSAnswers = append(msg.DNSAnswers, fmt.Sprintf("%s record", dnsTypeToString(a.Type)))
			}
			msg.DNSAnswerTypes = append(msg.DNSAnswerTypes, dnsTypeToString(a.Type))
		}
	}

	// Set short message
	if len(msg.DNSQuestions) > 0 {
		msg.ShortMessage = fmt.Sprintf("DNS %s: %s", msg.DNSType, strings.Join(msg.DNSQuestions, ", "))
	} else {
		msg.ShortMessage = fmt.Sprintf("DNS %s", msg.DNSType)
	}

	var fullMsg strings.Builder
	fullMsg.WriteString(msg.ShortMessage)
	fullMsg.WriteString("\n\nDNS Details:\n")
	fullMsg.WriteString(fmt.Sprintf("Type: %s\n", msg.DNSType))
	fullMsg.WriteString(fmt.Sprintf("Transaction ID: 0x%04x\n", event.TransactionID))
	fullMsg.WriteString(fmt.Sprintf("Flags: 0x%04x\n", event.DNSFlags))

	// Format questions section with proper indentation and numbering
	if len(msg.DNSQuestions) > 0 {
		fullMsg.WriteString("\nQuestions:\n")
		for i, q := range msg.DNSQuestions {
			fullMsg.WriteString(fmt.Sprintf("  %d. %s (%s)\n", i+1, q, msg.DNSQueryTypes[i]))
		}
	}

	// Format answers section with types and proper indentation
	if len(msg.DNSAnswers) > 0 {
		fullMsg.WriteString("\nAnswers:\n")
		for i, a := range msg.DNSAnswers {
			fullMsg.WriteString(fmt.Sprintf("  %d. %s (%s)\n", i+1, a, msg.DNSAnswerTypes[i]))
		}
	}
	fullMsg.WriteString(fmt.Sprintf("\nProcess Details:\n"))
	fullMsg.WriteString(fmt.Sprintf("Process: %s (PID: %d)\n", msg.ProcessName, msg.ProcessID))
	fullMsg.WriteString(fmt.Sprintf("Parent: %s (PPID: %d)\n", msg.ParentName, msg.ParentID))
	fullMsg.WriteString(fmt.Sprintf("\nConnection Details:\n"))
	fullMsg.WriteString(fmt.Sprintf("Source: %s:%d\n", msg.SourceIP, msg.SourcePort))
	fullMsg.WriteString(fmt.Sprintf("Destination: %s:%d\n", msg.DestIP, msg.DestPort))
	msg.FullMessage = fullMsg.String()

	return f.encoder.Encode(msg)
}

func (f *GELFFormatter) FormatTLS(event *types.UserSpaceTLSEvent, info *types.ProcessInfo) error {
	msg := gelfMessage{
		Version:        "1.1",
		Host:           f.getHostname(),
		Level:          6,
		Timestamp:      float64(BpfTimestampToTime(event.Timestamp).Unix()) + float64(BpfTimestampToTime(event.Timestamp).Nanosecond())/1000000000,
		TimestampHuman: BpfTimestampToTime(event.Timestamp).UTC().Format(time.RFC3339Nano),
		EventType:      "tls_handshake",
		EventCategory:  "network",
		ProcessUID:     info.ProcessUID,
	}

	// Generate correlation IDs
	msg.SessionUID = f.sessionUID
	msg.NetworkUID = GenerateBidirectionalConnID(event.Pid, event.Ppid,
		event.SourceIP, event.DestIP,
		event.SourcePort, event.DestPort)
	msg.CommunityID = GenerateCommunityID(
		event.SourceIP,
		event.DestIP,
		event.SourcePort,
		event.DestPort,
		event.Protocol,
		0) // default seed

	// Process info
	msg.ProcessID = int32(event.Pid)
	msg.ProcessName = event.Comm
	msg.ParentID = int32(event.Ppid)
	msg.ParentName = event.ParentComm

	// Network info
	msg.SourceIP = event.SourceIP.String()
	msg.SourcePort = int(event.SourcePort)
	msg.DestIP = event.DestIP.String()
	msg.DestPort = int(event.DestPort)

	// TLS specific fields
	msg.TLSVersion = formatTlsVersion(event.TLSVersion)
	msg.TLSSNI = event.SNI

	// Convert cipher suites to strings
	for _, cs := range event.CipherSuites {
		msg.TLSCipherSuites = append(msg.TLSCipherSuites, fmt.Sprintf("0x%04x", cs))
	}

	// JA4 fingerprinting
	msg.TLSJa4 = event.JA4
	msg.TLSJa4Hash = event.JA4Hash

	// Set short message
	if event.SNI != "" {
		msg.ShortMessage = fmt.Sprintf("TLS handshake: %s (%s)", msg.TLSSNI, msg.TLSVersion)
	} else {
		msg.ShortMessage = fmt.Sprintf("TLS handshake: %s", msg.TLSVersion)
	}

	var fullMsg strings.Builder
	fullMsg.WriteString(msg.ShortMessage)
	fullMsg.WriteString("\n\n")
	fullMsg.WriteString(fmt.Sprintf("TLS Details:\n"))
	fullMsg.WriteString(fmt.Sprintf("Version: %s\n", msg.TLSVersion))
	fullMsg.WriteString(fmt.Sprintf("Server Name: %s\n", msg.TLSSNI))
	if len(msg.TLSCipherSuites) > 0 {
		fullMsg.WriteString("\nSupported Cipher Suites:\n")
		for i, cs := range msg.TLSCipherSuites {
			fullMsg.WriteString(fmt.Sprintf("  %d. %s\n", i+1, cs))
		}
	}
	if msg.TLSJa4 != "" {
		fullMsg.WriteString(fmt.Sprintf("\nFingerprinting:\n"))
		fullMsg.WriteString(fmt.Sprintf("  JA4: %s\n", msg.TLSJa4))
		fullMsg.WriteString(fmt.Sprintf("  JA4 Hash: %s\n", msg.TLSJa4Hash))
	}
	fullMsg.WriteString(fmt.Sprintf("\nProcess Details:\n"))
	fullMsg.WriteString(fmt.Sprintf("Process: %s (PID: %d)\n", msg.ProcessName, msg.ProcessID))
	fullMsg.WriteString(fmt.Sprintf("Parent: %s (PPID: %d)\n", msg.ParentName, msg.ParentID))
	fullMsg.WriteString(fmt.Sprintf("\nConnection Details:\n"))
	fullMsg.WriteString(fmt.Sprintf("Source: %s:%d\n", msg.SourceIP, msg.SourcePort))
	fullMsg.WriteString(fmt.Sprintf("Destination: %s:%d\n", msg.DestIP, msg.DestPort))
	msg.FullMessage = fullMsg.String()

	return f.encoder.Encode(msg)
}

func (f *GELFFormatter) FormatSigmaMatch(match *types.SigmaMatch) error {
	msg := gelfMessage{
		Version:    "1.1",
		Host:       f.getHostname(),
		Level:      6, // Info level
		Timestamp:  float64(match.Timestamp.Unix()) + float64(match.Timestamp.Nanosecond())/1000000000,
		EventType:  "sigma_match",
		SessionUID: f.sessionUID,
	}

	// Add Sigma rule information
	msg.RuleID = match.RuleID
	msg.RuleName = match.RuleName
	msg.RuleLevel = match.RuleLevel
	msg.RuleDescription = match.RuleDescription
	msg.RuleReferences = match.RuleReferences
	msg.RuleTags = match.RuleTags
	if details, ok := match.MatchedFields["details"].(string); ok {
		msg.MatchDetails = details
	}

	// Add process context
	msg.ProcessID = int32(match.PID)
	if match.ProcessInfo != nil {
		msg.ProcessName = match.ProcessInfo.Comm
		msg.CmdLine = match.ProcessInfo.CmdLine
		msg.WorkingDir = match.ProcessInfo.WorkingDir
		msg.ParentID = int32(match.ProcessInfo.PPID)
		msg.Username = match.ProcessInfo.Username
	}

	// Add correlation IDs
	msg.ProcessUID = match.ProcessUID
	msg.CommunityID = match.CommunityID
	msg.ConversationID = match.ConversationID

	// Create short message (appears in log overview)
	msg.ShortMessage = fmt.Sprintf("sigma_match: %s (Level: %s)",
		match.RuleName, match.RuleLevel)
	if match.ProcessInfo != nil {
		msg.ShortMessage += fmt.Sprintf(" - Process: %s [%d]",
			match.ProcessInfo.Comm, match.PID)
	}

	// Create detailed full message
	var fullMsg strings.Builder
	fullMsg.WriteString(msg.ShortMessage)
	fullMsg.WriteString("\n\nRule Details:\n")
	fullMsg.WriteString(fmt.Sprintf("ID: %s\n", match.RuleID))
	fullMsg.WriteString(fmt.Sprintf("Description: %s\n", match.RuleDescription))
	fullMsg.WriteString(fmt.Sprintf("Match Details: %s\n", msg.MatchDetails))

	if len(match.RuleReferences) > 0 {
		fullMsg.WriteString("\nReferences:\n")
		for _, ref := range match.RuleReferences {
			fullMsg.WriteString(fmt.Sprintf("  - %s\n", ref))
		}
	}

	if len(match.RuleTags) > 0 {
		fullMsg.WriteString("\nTags:\n")
		for _, tag := range match.RuleTags {
			fullMsg.WriteString(fmt.Sprintf("  - %s\n", tag))
		}
	}

	if match.ProcessInfo != nil {
		fullMsg.WriteString("\nProcess Details:\n")
		fullMsg.WriteString(fmt.Sprintf("Name: %s (PID: %d)\n",
			match.ProcessInfo.Comm, match.PID))
		fullMsg.WriteString(fmt.Sprintf("Command: %s\n", match.ProcessInfo.CmdLine))
		fullMsg.WriteString(fmt.Sprintf("Working Directory: %s\n",
			match.ProcessInfo.WorkingDir))
		fullMsg.WriteString(fmt.Sprintf("Username: %s\n", match.ProcessInfo.Username))
	}

	msg.FullMessage = fullMsg.String()
	msg.TimestampHuman = match.Timestamp.UTC().Format(time.RFC3339Nano)

	return f.encoder.Encode(msg)
}

func (f *GELFFormatter) FormatBinary(binary *types.BinaryInfo) error {
	msg := gelfMessage{
		Version:        "1.1",
		Host:           f.getHostname(),
		Level:          6, // Info level
		Timestamp:      float64(time.Now().Unix()) + float64(time.Now().Nanosecond())/1000000000,
		TimestampHuman: time.Now().UTC().Format(time.RFC3339Nano),
		EventType:      "binary_seen",
		SessionUID:     f.sessionUID,
	}

	// Create message content
	elfType := ""
	if binary.IsELF {
		elfType = binary.ELFType + " "
	}

	// Add basic binary fields (GELF requires _ prefix for custom fields)
	msg.BinaryPath = binary.Path
	msg.BinaryMd5 = binary.MD5Hash
	msg.BinarySha256 = binary.SHA256Hash
	msg.BinarySize = binary.FileSize
	msg.BinaryFirstSeen = binary.FirstSeen.Format(time.RFC3339Nano)
	msg.BinaryModTime = binary.ModTime.Format(time.RFC3339Nano)

	// Add ELF information
	if binary.IsELF {
		msg.BinaryIsElf = true
		msg.BinaryElfType = binary.ELFType
		msg.BinaryArchitecture = binary.Architecture
		msg.BinaryInterpreter = binary.Interpreter
		msg.BinaryImportCount = binary.ImportCount
		msg.BinaryExportCount = binary.ExportCount
		msg.BinaryStaticallyLinked = binary.IsStaticallyLinked
		msg.BinaryHasDebugInfo = binary.HasDebugInfo

		// Libraries need to be JSON-encoded
		if len(binary.ImportedLibraries) > 0 {
			librariesJSON, _ := json.Marshal(binary.ImportedLibraries)
			msg.BinaryImportedLibraries = string(librariesJSON)
		}
	}

	// Add package information
	pkgInfo := ""
	if binary.IsFromPackage {
		msg.BinaryFromPackage = true
		msg.BinaryPackageName = binary.PackageName
		msg.BinaryPackageVersion = binary.PackageVersion
		msg.BinaryPackageVerified = binary.PackageVerified
		msg.BinaryPackageManager = binary.PackageManager

		pkgInfo = fmt.Sprintf(" (Package: %s %s", binary.PackageName, binary.PackageVersion)
		if !binary.PackageVerified {
			pkgInfo += " [MODIFIED]"
		}
		pkgInfo += ")"
	}

	msg.ShortMessage = fmt.Sprintf("Binary observed: %s (%s%s)%s",
		binary.Path,
		elfType,
		binary.Architecture,
		pkgInfo)

	// Create detailed full message
	var fullMsg strings.Builder
	fullMsg.WriteString(msg.ShortMessage)
	fullMsg.WriteString("\n\n")
	fullMsg.WriteString(fmt.Sprintf("Binary Details:\n"))
	fullMsg.WriteString(fmt.Sprintf("Path: %s\n", binary.Path))
	fullMsg.WriteString(fmt.Sprintf("MD5: %s\n", binary.MD5Hash))
	if binary.SHA256Hash != "" {
		fullMsg.WriteString(fmt.Sprintf("SHA256: %s\n", binary.SHA256Hash))
	}
	fullMsg.WriteString(fmt.Sprintf("Size: %d bytes\n", binary.FileSize))
	fullMsg.WriteString(fmt.Sprintf("Modified: %s\n", binary.ModTime.Format(time.RFC3339)))
	fullMsg.WriteString(fmt.Sprintf("First Seen: %s\n", binary.FirstSeen.Format(time.RFC3339)))

	if binary.IsELF {
		fullMsg.WriteString(fmt.Sprintf("\nELF Information:\n"))
		fullMsg.WriteString(fmt.Sprintf("Type: %s\n", binary.ELFType))
		fullMsg.WriteString(fmt.Sprintf("Architecture: %s\n", binary.Architecture))
		if binary.Interpreter != "" {
			fullMsg.WriteString(fmt.Sprintf("Interpreter: %s\n", binary.Interpreter))
		}
		fullMsg.WriteString(fmt.Sprintf("Import Count: %d\n", binary.ImportCount))
		fullMsg.WriteString(fmt.Sprintf("Export Count: %d\n", binary.ExportCount))
		fullMsg.WriteString(fmt.Sprintf("Statically Linked: %v\n", binary.IsStaticallyLinked))
		fullMsg.WriteString(fmt.Sprintf("Debug Info: %v\n", binary.HasDebugInfo))

		if len(binary.ImportedLibraries) > 0 {
			fullMsg.WriteString("\nImported Libraries:\n")
			for i, lib := range binary.ImportedLibraries {
				fullMsg.WriteString(fmt.Sprintf("  %d. %s\n", i+1, lib))
			}
		}
	}

	if binary.IsFromPackage {
		fullMsg.WriteString(fmt.Sprintf("\nPackage Information:\n"))
		fullMsg.WriteString(fmt.Sprintf("Package: %s\n", binary.PackageName))
		fullMsg.WriteString(fmt.Sprintf("Version: %s\n", binary.PackageVersion))
		fullMsg.WriteString(fmt.Sprintf("Manager: %s\n", binary.PackageManager))
		fullMsg.WriteString(fmt.Sprintf("Verified: %v\n", binary.PackageVerified))
		if !binary.PackageVerified {
			fullMsg.WriteString("*** BINARY MODIFIED FROM PACKAGE ***\n")
		}
	}

	msg.FullMessage = fullMsg.String()

	return f.encoder.Encode(msg)
}

func (f *GELFFormatter) getHostname() string {
	// Check for hostname first
	if f.hostname != "" && f.hostname != "unknown" {
		return f.hostname
	}
	// Fall back to IP if hostname not set
	if f.hostIP != "" {
		return f.hostIP
	}
	// Final fallback
	return "unknown"
}
