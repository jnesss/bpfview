// ecs.go
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

// ECSFormatter implements the EventFormatter interface for Elastic Common Schema format
// ECS Reference: https://www.elastic.co/guide/en/ecs/current/ecs-reference.html
type ECSFormatter struct {
	encoder      *json.Encoder
	output       io.Writer
	hostname     string
	hostIP       string
	sessionUID   string
	sigmaEnabled bool
}

// ECS base event structure
type ecsEvent struct {
	// ECS base fields
	Timestamp string `json:"@timestamp"`
	Version   string `json:"ecs.version"`    // ECS version
	Type      string `json:"event.type"`     // e.g., process, network, dns
	Subtype   string `json:"event.subtype"`  // e.g., dns_query, network_connection
	Category  string `json:"event.category"` // e.g., process, network
	Kind      string `json:"event.kind"`     // e.g., event, alert, metric
	Dataset   string `json:"event.dataset"`  // Source of the event (bpfview)
	Sequence  string `json:"event.sequence"` // Session UID
	Action    string `json:"event.action"`   // Specific action being taken
	Outcome   string `json:"event.outcome"`  // success, failure, unknown
	Message   string `json:"message,omitempty"`

	// Host information
	HostName   string `json:"host.name,omitempty"`
	HostIP     string `json:"host.ip,omitempty"`
	HostOS     string `json:"host.os.type"`
	HostKernel string `json:"host.os.kernel"`

	// Process information
	ProcessName             string   `json:"process.name,omitempty"`
	ProcessPID              int64    `json:"process.pid,omitempty"`
	ProcessExecutable       string   `json:"process.executable,omitempty"`
	ProcessCommandLine      string   `json:"process.command_line,omitempty"`
	ProcessWorkingDirectory string   `json:"process.working_directory,omitempty"`
	ProcessHashMD5          string   `json:"process.hash.md5,omitempty"`
	ProcessEnv              []string `json:"process.env,omitempty"`
	ProcessStart            string   `json:"process.start,omitempty"`
	ProcessEnd              string   `json:"process.end,omitempty"`
	ProcessExitCode         int64    `json:"process.exit_code,omitempty"`
	ProcessExitDescription  string   `json:"process.exit_description,omitempty"`
	ProcessDuration         string   `json:"process.duration,omitempty"`

	// Parent process
	ParentProcessName        string `json:"process.parent.name,omitempty"`
	ParentProcessPID         int64  `json:"process.parent.pid,omitempty"`
	ParentProcessExecutable  string `json:"process.parent.executable,omitempty"`
	ParentProcessCommandLine string `json:"process.parent.command_line,omitempty"`
	ParentProcessHashMD5     string `json:"process.parent.hash.md5,omitempty"`
	ParentProcessStart       string `json:"process.parent.start,omitempty"`

	// User information
	UserID   string `json:"user.id,omitempty"`
	UserName string `json:"user.name,omitempty"`
	GroupID  string `json:"user.group.id,omitempty"`

	// User information
	ParentUserID   string `json:"user.parent.id,omitempty"`
	ParentUserName string `json:"user.parent.name,omitempty"`
	ParentGroupID  string `json:"user.parent.group.id,omitempty"`

	// Container information
	ContainerID string `json:"container.id,omitempty"`

	// Network information
	NetworkType          string `json:"network.type,omitempty"`
	NetworkProtocol      string `json:"network.protocol,omitempty"`
	NetworkBytes         int64  `json:"network.bytes,omitempty"`
	NetworkDirection     string `json:"network.direction,omitempty"`
	NetworkDirectionDesc string `json:"network.direction_description,omitempty"`

	// TCP flags
	NetworkTCPFlags    string `json:"network.tcp.flags,omitempty"`
	NetworkTCPFlagsRaw uint8  `json:"network.tcp.flags.raw,omitempty"`
	NetworkTCPFlagFIN  bool   `json:"network.tcp.flags.fin,omitempty"`
	NetworkTCPFlagSYN  bool   `json:"network.tcp.flags.syn,omitempty"`
	NetworkTCPFlagRST  bool   `json:"network.tcp.flags.rst,omitempty"`
	NetworkTCPFlagPSH  bool   `json:"network.tcp.flags.psh,omitempty"`
	NetworkTCPFlagACK  bool   `json:"network.tcp.flags.ack,omitempty"`
	NetworkTCPFlagURG  bool   `json:"network.tcp.flags.urg,omitempty"`
	NetworkTCPFlagECE  bool   `json:"network.tcp.flags.ece,omitempty"`
	NetworkTCPFlagCWR  bool   `json:"network.tcp.flags.cwr,omitempty"`

	// Source/Destination
	SourceIP          string `json:"source.ip,omitempty"`
	SourcePort        int64  `json:"source.port,omitempty"`
	DestinationIP     string `json:"destination.ip,omitempty"`
	DestinationPort   int64  `json:"destination.port,omitempty"`
	DestinationDomain string `json:"destination.domain,omitempty"`

	// DNS specific fields
	DNSType         string   `json:"dns.type,omitempty"`
	DNSQuestion     []string `json:"dns.question.name,omitempty"`
	DNSAnswers      []string `json:"dns.answers.name,omitempty"`
	DNSAnswerType   []string `json:"dns.answers.type,omitempty"`
	DNSOpCode       string   `json:"dns.op_code,omitempty"`
	DNSFlags        []string `json:"dns.flags,omitempty"`
	DNSResponseCode string   `json:"dns.response_code,omitempty"`

	// TLS specific fields
	TLSVersion         string   `json:"tls.version,omitempty"`
	TLSServerName      string   `json:"tls.server_name,omitempty"`
	TLSCipherSuite     string   `json:"tls.cipher,omitempty"`
	TLSClientJa4       string   `json:"tls.client.ja4,omitempty"`
	TLSClientJa4Hash   string   `json:"tls.client.ja4_hash,omitempty"`
	TLSClientSupported []string `json:"tls.client.supported_ciphers,omitempty"`

	// Rule information
	RuleID           string                 `json:"rule.id,omitempty"`
	RuleName         string                 `json:"rule.name,omitempty"`
	RuleDescription  string                 `json:"rule.description,omitempty"`
	RuleLevel        string                 `json:"rule.level,omitempty"`
	RuleReference    []string               `json:"rule.reference,omitempty"`
	RuleTags         []string               `json:"rule.tags,omitempty"`
	RuleMatchDetails string                 `json:"rule.matched_details,omitempty"`
	DetectionFields  map[string]interface{} `json:"rule.matched_fields,omitempty"`

	// File/Binary information (ECS file.* fields)
	FilePath       string `json:"file.path,omitempty"`
	FileSize       int64  `json:"file.size,omitempty"`
	FileHashMD5    string `json:"file.hash.md5,omitempty"`
	FileHashSHA256 string `json:"file.hash.sha256,omitempty"`
	FileCreatedAt  string `json:"file.created,omitempty"`
	FileModifiedAt string `json:"file.mtime,omitempty"`
	FileType       string `json:"file.type,omitempty"`
	FileExtension  string `json:"file.extension,omitempty"`

	// ELF-specific fields can use custom fields
	FileMimeType string                 `json:"file.mime_type,omitempty"`
	FileELF      map[string]interface{} `json:"file.elf,omitempty"`
	FilePackage  map[string]string      `json:"file.package,omitempty"`

	// Package info (using ECS "package" namespace)
	PackageName     string `json:"package.name,omitempty"`
	PackageVersion  string `json:"package.version,omitempty"`
	PackageType     string `json:"package.type,omitempty"` // rpm, deb, etc.
	PackageVerified bool   `json:"package.verified,omitempty"`

	// Correlation IDs
	Labels map[string]string `json:"labels,omitempty"`
}

func NewECSFormatter(output io.Writer, hostname, hostIP, sessionUID string, enableSigma bool) *ECSFormatter {
	f := &ECSFormatter{
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

func (f *ECSFormatter) Initialize() error {
	return nil
}

func (f *ECSFormatter) Close() error {
	return nil
}

func (f *ECSFormatter) FormatProcess(event *types.ProcessEvent, info *types.ProcessInfo, parentinfo *types.ProcessInfo) error {
	ecsEvent := f.createBaseEvent()
	ecsEvent.Type = "process"
	ecsEvent.Category = "process"
	ecsEvent.Kind = "event"

	// Set process action based on event type
	if event.EventType == types.EVENT_PROCESS_EXEC {
		ecsEvent.Action = "process_exec"
		ecsEvent.Outcome = "success"
		ecsEvent.Message = fmt.Sprintf("process_exec: %s (PID: %d)", info.Comm, info.PID)
	} else if event.EventType == types.EVENT_PROCESS_FORK {
		ecsEvent.Action = "process_fork"
		ecsEvent.Outcome = "success"
		ecsEvent.Message = fmt.Sprintf("process_fork: %s (PID: %d)", info.Comm, info.PID)
	} else {
		ecsEvent.Action = "process_exit"
		ecsEvent.Outcome = fmt.Sprintf("exit_code_%d", info.ExitCode)
		ecsEvent.Message = fmt.Sprintf("process_exit: %s (PID: %d)", info.Comm, info.PID)
	}

	// Process information
	ecsEvent.ProcessName = info.Comm
	ecsEvent.ProcessPID = int64(info.PID)
	ecsEvent.ProcessExecutable = info.ExePath
	ecsEvent.ProcessCommandLine = info.CmdLine
	ecsEvent.ProcessWorkingDirectory = info.WorkingDir
	ecsEvent.ProcessHashMD5 = info.BinaryHash

	// Parent process (using what's in the event)
	ecsEvent.ParentProcessPID = int64(info.PPID)
	parentComm := string(bytes.TrimRight(event.ParentComm[:], "\x00"))
	ecsEvent.ParentProcessName = parentComm

	// User information
	ecsEvent.UserID = fmt.Sprintf("%d", info.UID)
	ecsEvent.UserName = info.Username
	ecsEvent.GroupID = fmt.Sprintf("%d", info.GID)

	// Parent process details if available
	if parentinfo != nil {
		ecsEvent.ParentProcessExecutable = parentinfo.ExePath
		ecsEvent.ParentProcessCommandLine = parentinfo.CmdLine
		ecsEvent.ParentProcessHashMD5 = parentinfo.BinaryHash
		if !parentinfo.StartTime.IsZero() {
			ecsEvent.ParentProcessStart = parentinfo.StartTime.UTC().Format(time.RFC3339Nano)
		}

		// User information
		ecsEvent.ParentUserID = fmt.Sprintf("%d", parentinfo.UID)
		ecsEvent.ParentUserName = parentinfo.Username
		ecsEvent.ParentGroupID = fmt.Sprintf("%d", parentinfo.GID)
	}

	// Container ID if available
	if info.ContainerID != "" && info.ContainerID != "-" {
		ecsEvent.ContainerID = info.ContainerID
	}

	// Process timing
	if !info.StartTime.IsZero() {
		ecsEvent.ProcessStart = info.StartTime.UTC().Format(time.RFC3339Nano)
	}
	if !info.ExitTime.IsZero() {
		ecsEvent.ProcessEnd = info.ExitTime.UTC().Format(time.RFC3339Nano)
		ecsEvent.ProcessExitCode = int64(info.ExitCode)

		// Add exit code description
		switch info.ExitCode {
		case 0:
			ecsEvent.ProcessExitDescription = "Success"
		case 1:
			ecsEvent.ProcessExitDescription = "General error"
		case 126:
			ecsEvent.ProcessExitDescription = "Command not executable"
		case 127:
			ecsEvent.ProcessExitDescription = "Command not found"
		case 130:
			ecsEvent.ProcessExitDescription = "Terminated by Ctrl+C"
		case 255:
			ecsEvent.ProcessExitDescription = "Exit status out of range or SSH closed"
		}

		if !info.StartTime.IsZero() {
			ecsEvent.ProcessDuration = info.ExitTime.Sub(info.StartTime).String()
		}
	}

	if info.PackageName != "" || info.IsFromPackage {
		ecsEvent.PackageName = info.PackageName
		ecsEvent.PackageVersion = info.PackageVersion
		ecsEvent.PackageType = info.PackageManager
		ecsEvent.PackageVerified = info.PackageVerified
	}

	var fingerprint string
	if info.Fingerprint != "" {
		if info.ParentFingerprint != "" {
			fingerprint = fmt.Sprintf("%v_%v", info.Fingerprint, info.ParentFingerprint)
		} else {
			fingerprint = info.Fingerprint
		}
	}

	// Correlation IDs
	ecsEvent.Labels = map[string]string{
		"session_uid": f.sessionUID,
		"process_uid": info.ProcessUID,
		"fingerprint": fingerprint,
	}

	return f.encoder.Encode(ecsEvent)
}

func (f *ECSFormatter) FormatNetwork(event *types.NetworkEvent, info *types.ProcessInfo) error {
	ecsEvent := f.createBaseEvent()
	ecsEvent.Type = "network_flow"
	ecsEvent.Category = "network"
	ecsEvent.Kind = "event"
	ecsEvent.Action = "network_flow"

	// Network specific information
	ecsEvent.NetworkType = "ipv4"
	ecsEvent.NetworkProtocol = strings.ToLower(protocolToString(event.Protocol))
	ecsEvent.NetworkBytes = int64(event.BytesCount)
	if event.Direction == types.FLOW_INGRESS {
		ecsEvent.NetworkDirection = "ingress"
		ecsEvent.NetworkDirectionDesc = "Incoming traffic from external host"
	} else {
		ecsEvent.NetworkDirection = "egress"
		ecsEvent.NetworkDirectionDesc = "Outgoing traffic to external service"
	}
	if event.Protocol == 6 { // TCP
		ecsEvent.NetworkTCPFlags = FormatTCPFlags(event.TCPFlags)
		ecsEvent.NetworkTCPFlagsRaw = event.TCPFlags

		// Also add individual flag fields for better Elastic querying
		if (event.TCPFlags & 0x01) != 0 {
			ecsEvent.NetworkTCPFlagFIN = true
		}
		if (event.TCPFlags & 0x02) != 0 {
			ecsEvent.NetworkTCPFlagSYN = true
		}
		if (event.TCPFlags & 0x04) != 0 {
			ecsEvent.NetworkTCPFlagRST = true
		}
		if (event.TCPFlags & 0x08) != 0 {
			ecsEvent.NetworkTCPFlagPSH = true
		}
		if (event.TCPFlags & 0x10) != 0 {
			ecsEvent.NetworkTCPFlagACK = true
		}
		if (event.TCPFlags & 0x20) != 0 {
			ecsEvent.NetworkTCPFlagURG = true
		}
		if (event.TCPFlags & 0x40) != 0 {
			ecsEvent.NetworkTCPFlagECE = true
		}
		if (event.TCPFlags & 0x80) != 0 {
			ecsEvent.NetworkTCPFlagCWR = true
		}

	}

	// Source and destination
	ecsEvent.SourceIP = ipToString(event.SrcIP)
	ecsEvent.SourcePort = int64(event.SrcPort)
	ecsEvent.DestinationIP = ipToString(event.DstIP)
	ecsEvent.DestinationPort = int64(event.DstPort)

	// Process information (from event and provided info)
	ecsEvent.ProcessName = string(bytes.TrimRight(event.Comm[:], "\x00"))
	ecsEvent.ProcessPID = int64(event.Pid)
	ecsEvent.ParentProcessName = string(bytes.TrimRight(event.ParentComm[:], "\x00"))
	ecsEvent.ParentProcessPID = int64(event.Ppid)

	// Additional process info if provided
	if info != nil {
		ecsEvent.ProcessExecutable = info.ExePath
		ecsEvent.ProcessCommandLine = info.CmdLine
		ecsEvent.ProcessWorkingDirectory = info.WorkingDir
		ecsEvent.ProcessHashMD5 = info.BinaryHash
		ecsEvent.UserName = info.Username
		ecsEvent.ContainerID = info.ContainerID
	}

	ecsEvent.Message = fmt.Sprintf("Network connection: %s:%d → %s:%d (%s)",
		ecsEvent.SourceIP, ecsEvent.SourcePort,
		ecsEvent.DestinationIP, ecsEvent.DestinationPort,
		ecsEvent.NetworkProtocol)

	// Correlation IDs
	ecsEvent.Labels = map[string]string{
		"session_uid": f.sessionUID,
		"process_uid": info.ProcessUID,
		"network_uid": GenerateBidirectionalConnID(event.Pid, event.Ppid,
			uint32ToNetIP(event.SrcIP),
			uint32ToNetIP(event.DstIP),
			event.SrcPort, event.DstPort),
		"community_id": GenerateCommunityID(
			uint32ToNetIP(event.SrcIP),
			uint32ToNetIP(event.DstIP),
			event.SrcPort,
			event.DstPort,
			event.Protocol,
			0),
	}

	return f.encoder.Encode(ecsEvent)
}

func (f *ECSFormatter) FormatDNS(event *types.UserSpaceDNSEvent, info *types.ProcessInfo) error {
	ecsEvent := f.createBaseEvent()
	ecsEvent.Type = "dns"
	ecsEvent.Category = "network"
	ecsEvent.Kind = "event"

	if event.IsResponse {
		ecsEvent.Action = "dns_response"
	} else {
		ecsEvent.Action = "dns_query"
	}

	// DNS specific fields
	ecsEvent.DNSType = ecsEvent.Action
	for _, q := range event.Questions {
		ecsEvent.DNSQuestion = append(ecsEvent.DNSQuestion, q.Name)
	}

	if event.IsResponse {
		for _, a := range event.Answers {
			switch a.Type {
			case 1, 28: // A or AAAA
				if a.IPAddress != nil {
					ecsEvent.DNSAnswers = append(ecsEvent.DNSAnswers, a.IPAddress.String())
				}
			case 5: // CNAME
				ecsEvent.DNSAnswers = append(ecsEvent.DNSAnswers, a.CName)
			default:
				ecsEvent.DNSAnswers = append(ecsEvent.DNSAnswers, fmt.Sprintf("%s record", dnsTypeToString(a.Type)))
			}
			ecsEvent.DNSAnswerType = append(ecsEvent.DNSAnswerType, dnsTypeToString(a.Type))
		}
	}

	if event.IsResponse {
		if len(event.Questions) > 0 {
			ecsEvent.Message = fmt.Sprintf("DNS response: %s", strings.Join(ecsEvent.DNSQuestion, ", "))
		} else {
			ecsEvent.Message = "DNS response"
		}
	} else {
		if len(event.Questions) > 0 {
			ecsEvent.Message = fmt.Sprintf("DNS query: %s", strings.Join(ecsEvent.DNSQuestion, ", "))
		} else {
			ecsEvent.Message = "DNS query"
		}
	}

	// Network information
	ecsEvent.NetworkType = "ipv4"
	ecsEvent.NetworkProtocol = "dns"
	ecsEvent.SourceIP = event.SourceIP.String()
	ecsEvent.SourcePort = int64(event.SourcePort)
	ecsEvent.DestinationIP = event.DestIP.String()
	ecsEvent.DestinationPort = int64(event.DestPort)

	// Process information
	ecsEvent.ProcessName = event.Comm
	ecsEvent.ProcessPID = int64(event.Pid)
	ecsEvent.ParentProcessName = event.ParentComm
	ecsEvent.ParentProcessPID = int64(event.Ppid)

	// Add correlation IDs in labels
	ecsEvent.Labels = map[string]string{
		"session_uid": f.sessionUID,
		"process_uid": info.ProcessUID,
		"network_uid": GenerateBidirectionalConnID(event.Pid, event.Ppid, event.SourceIP, event.DestIP, event.SourcePort, event.DestPort),
		"community_id": GenerateCommunityID(
			event.SourceIP,
			event.DestIP,
			event.SourcePort,
			event.DestPort,
			17, // UDP
			0),
		"conversation_uid": event.ConversationID,
	}

	return f.encoder.Encode(ecsEvent)
}

func (f *ECSFormatter) FormatTLS(event *types.UserSpaceTLSEvent, info *types.ProcessInfo) error {
	ecsEvent := f.createBaseEvent()
	ecsEvent.Type = "tls"
	ecsEvent.Category = "network"
	ecsEvent.Kind = "event"
	ecsEvent.Action = "tls_handshake"

	// TLS specific fields
	ecsEvent.TLSVersion = formatTlsVersion(event.TLSVersion)
	ecsEvent.TLSServerName = event.SNI
	ecsEvent.TLSClientJa4 = event.JA4
	ecsEvent.TLSClientJa4Hash = event.JA4Hash

	// Cipher suites
	if len(event.CipherSuites) > 0 {
		cipherStrs := make([]string, len(event.CipherSuites))
		for i, cs := range event.CipherSuites {
			cipherStrs[i] = fmt.Sprintf("0x%04x", cs)
		}
		ecsEvent.TLSClientSupported = cipherStrs
		ecsEvent.TLSCipherSuite = cipherStrs[0] // Use first as selected cipher
	}

	// Network information
	ecsEvent.NetworkType = "ipv4"
	ecsEvent.NetworkProtocol = "tls"
	ecsEvent.SourceIP = event.SourceIP.String()
	ecsEvent.SourcePort = int64(event.SourcePort)
	ecsEvent.DestinationIP = event.DestIP.String()
	ecsEvent.DestinationPort = int64(event.DestPort)

	// Process information
	ecsEvent.ProcessName = event.Comm
	ecsEvent.ProcessPID = int64(event.Pid)
	ecsEvent.ParentProcessName = event.ParentComm
	ecsEvent.ParentProcessPID = int64(event.Ppid)

	if event.SNI != "" {
		ecsEvent.Message = fmt.Sprintf("TLS handshake: %s (%s)", event.SNI, formatTlsVersion(event.TLSVersion))
	} else {
		ecsEvent.Message = fmt.Sprintf("TLS handshake: %s", formatTlsVersion(event.TLSVersion))
	}

	// Add correlation IDs in labels
	ecsEvent.Labels = map[string]string{
		"session_uid": f.sessionUID,
		"process_uid": info.ProcessUID,
		"network_uid": GenerateBidirectionalConnID(event.Pid, event.Ppid, event.SourceIP, event.DestIP, event.SourcePort, event.DestPort),
		"community_id": GenerateCommunityID(
			event.SourceIP,
			event.DestIP,
			event.SourcePort,
			event.DestPort,
			event.Protocol,
			0),
	}

	return f.encoder.Encode(ecsEvent)
}

func (f *ECSFormatter) FormatSigmaMatch(match *types.SigmaMatch) error {
	ecsEvent := f.createBaseEvent()

	// Event classification
	ecsEvent.Kind = "alert"
	ecsEvent.Type = "sigma"
	ecsEvent.Subtype = match.DetectionSource // "process_creation", "dns_query", "network_connection"
	ecsEvent.Action = "detection"
	ecsEvent.Outcome = "success"

	// Set event category based on detection source, matching JSON formatter approach
	switch match.DetectionSource {
	case "process_creation":
		ecsEvent.Category = "process"
	case "network_connection", "dns_query":
		ecsEvent.Category = "network"
	}

	// Process information
	if match.ProcessInfo != nil {
		ecsEvent.ProcessName = match.ProcessInfo.Comm
		ecsEvent.ProcessPID = int64(match.ProcessInfo.PID)
		ecsEvent.ProcessExecutable = match.ProcessInfo.ExePath
		ecsEvent.ProcessCommandLine = match.ProcessInfo.CmdLine
		ecsEvent.ProcessWorkingDirectory = match.ProcessInfo.WorkingDir
		ecsEvent.ProcessHashMD5 = match.ProcessInfo.BinaryHash
		ecsEvent.ProcessEnv = match.ProcessInfo.Environment
		ecsEvent.UserName = match.ProcessInfo.Username
		ecsEvent.UserID = fmt.Sprintf("%d", match.ProcessInfo.UID)
		ecsEvent.GroupID = fmt.Sprintf("%d", match.ProcessInfo.GID)
		ecsEvent.ContainerID = match.ProcessInfo.ContainerID

		// Process timing
		if !match.ProcessInfo.StartTime.IsZero() {
			ecsEvent.ProcessStart = match.ProcessInfo.StartTime.UTC().Format(time.RFC3339Nano)
		}
		if !match.ProcessInfo.ExitTime.IsZero() {
			ecsEvent.ProcessEnd = match.ProcessInfo.ExitTime.UTC().Format(time.RFC3339Nano)
			ecsEvent.ProcessExitCode = int64(match.ProcessInfo.ExitCode)
			if !match.ProcessInfo.StartTime.IsZero() {
				ecsEvent.ProcessDuration = match.ProcessInfo.ExitTime.Sub(match.ProcessInfo.StartTime).String()
			}
		}
	}

	// Parent process details
	if match.ParentInfo != nil {
		ecsEvent.ParentProcessName = match.ParentInfo.Comm
		ecsEvent.ParentProcessPID = int64(match.ParentInfo.PID)
		ecsEvent.ParentProcessExecutable = match.ParentInfo.ExePath
		ecsEvent.ParentProcessCommandLine = match.ParentInfo.CmdLine
		ecsEvent.ParentProcessHashMD5 = match.ParentInfo.BinaryHash

		// Add start time if available
		if !match.ParentInfo.StartTime.IsZero() {
			ecsEvent.ParentProcessStart = match.ParentInfo.StartTime.UTC().Format(time.RFC3339Nano)
		}
	}

	// Network details for network-based detections
	if match.DetectionSource == "dns_query" || match.DetectionSource == "network_connection" {
		// Core network fields
		ecsEvent.NetworkType = "ipv4"

		// Populate fields from EventData map
		if srcIP, ok := match.EventData["SourceIp"].(string); ok {
			ecsEvent.SourceIP = srcIP
		}
		if srcPort, ok := match.EventData["SourcePort"].(uint16); ok {
			ecsEvent.SourcePort = int64(srcPort)
		}
		if dstIP, ok := match.EventData["DestinationIp"].(string); ok {
			ecsEvent.DestinationIP = dstIP
		}
		if dstPort, ok := match.EventData["DestinationPort"].(uint16); ok {
			ecsEvent.DestinationPort = int64(dstPort)
		}
		if protocol, ok := match.EventData["Protocol"].(string); ok {
			ecsEvent.NetworkProtocol = strings.ToLower(protocol)
		}
		if direction, ok := match.EventData["Direction"].(string); ok {
			ecsEvent.NetworkDirection = direction
			// Add direction description like in JSON formatter
			if direction == "ingress" {
				ecsEvent.NetworkDirectionDesc = "Incoming traffic from external host"
			} else if direction == "egress" {
				ecsEvent.NetworkDirectionDesc = "Outgoing traffic to external service"
			}
		}

		// DNS-specific fields
		if hostname, ok := match.EventData["DestinationHostname"].(string); ok {
			ecsEvent.DestinationDomain = hostname
		}
	}

	// Rule information
	ecsEvent.RuleID = match.RuleID
	ecsEvent.RuleName = match.RuleName
	ecsEvent.RuleDescription = match.RuleDescription
	ecsEvent.RuleLevel = match.RuleLevel
	ecsEvent.RuleReference = match.RuleReferences
	ecsEvent.RuleTags = match.RuleTags

	// Detection details
	if details, ok := match.MatchedFields["details"].(string); ok {
		ecsEvent.RuleMatchDetails = details
	}
	ecsEvent.DetectionFields = match.MatchedFields

	// Correlation IDs
	ecsEvent.Labels = map[string]string{
		"session_uid": f.sessionUID,
		"process_uid": match.ProcessUID,
	}

	if match.NetworkUID != "" {
		ecsEvent.Labels["network_uid"] = match.NetworkUID
	}
	if match.ConversationID != "" {
		ecsEvent.Labels["dns_conversation_uid"] = match.ConversationID
	}
	if match.CommunityID != "" {
		ecsEvent.Labels["community_id"] = match.CommunityID
	}

	// Message formatting
	ecsEvent.Message = fmt.Sprintf("Sigma rule match: %s (Level: %s)",
		match.RuleName, match.RuleLevel)
	if match.ProcessInfo != nil {
		ecsEvent.Message += fmt.Sprintf(" - Process: %s [%d]",
			match.ProcessInfo.Comm, match.ProcessInfo.PID)
	}

	return f.encoder.Encode(ecsEvent)
}

func (f *ECSFormatter) FormatBinary(binary *types.BinaryInfo) error {
	ecsEvent := f.createBaseEvent()
	ecsEvent.Type = "binary"
	ecsEvent.Category = "file"
	ecsEvent.Kind = "event"
	ecsEvent.Action = "binary_observed"

	// Set standard ECS file fields
	ecsEvent.FilePath = binary.Path
	ecsEvent.FileSize = binary.FileSize
	ecsEvent.FileHashMD5 = binary.MD5Hash
	ecsEvent.FileHashSHA256 = binary.SHA256Hash
	ecsEvent.FileCreatedAt = binary.FirstSeen.Format(time.RFC3339Nano)
	ecsEvent.FileModifiedAt = binary.ModTime.Format(time.RFC3339Nano)

	// Create message
	elfType := ""
	if binary.IsELF {
		elfType = binary.ELFType
		ecsEvent.FileType = "elf"

		// Add ELF-specific information
		ecsEvent.FileELF = map[string]interface{}{
			"type":                 binary.ELFType,
			"architecture":         binary.Architecture,
			"interpreter":          binary.Interpreter,
			"is_statically_linked": binary.IsStaticallyLinked,
			"has_debug_info":       binary.HasDebugInfo,
			"import_count":         binary.ImportCount,
			"export_count":         binary.ExportCount,
			"imported_libraries":   binary.ImportedLibraries,
		}

		// Set appropriate mime type
		if binary.ELFType == "executable" {
			ecsEvent.FileMimeType = "application/x-executable"
		} else if binary.ELFType == "shared object" {
			ecsEvent.FileMimeType = "application/x-sharedlib"
		}
	}

	pkgInfo := ""
	if binary.IsFromPackage {
		ecsEvent.FilePackage = map[string]string{
			"name":     binary.PackageName,
			"version":  binary.PackageVersion,
			"manager":  binary.PackageManager,
			"verified": fmt.Sprintf("%t", binary.PackageVerified),
		}
		if binary.PackageVerified {
			pkgInfo = fmt.Sprintf(" (package: %s)", binary.PackageName)
		} else {
			pkgInfo = fmt.Sprintf(" (modified package: %s)", binary.PackageName)
		}

	}

	// Set message
	ecsEvent.Message = fmt.Sprintf("Binary observed: %s (%s %s)%s",
		binary.Path, elfType, binary.Architecture, pkgInfo)

	// Set correlation IDs
	ecsEvent.Labels = map[string]string{
		"session_uid": f.sessionUID,
		"binary_hash": binary.MD5Hash,
	}

	return f.encoder.Encode(ecsEvent)
}

func (f *ECSFormatter) createBaseEvent() ecsEvent {
	return ecsEvent{
		Timestamp:  time.Now().UTC().Format(time.RFC3339Nano),
		Version:    "8.12.0", // Current ECS version
		Dataset:    "bpfview",
		Sequence:   f.sessionUID,
		HostName:   f.hostname,
		HostIP:     f.hostIP,
		HostOS:     "linux",
		HostKernel: "linux",
	}
}
