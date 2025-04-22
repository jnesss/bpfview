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

type JSONFormatter struct {
	encoder      *json.Encoder
	output       io.Writer
	hostname     string
	hostIP       string
	sessionUID   string
	sigmaEnabled bool
}

// Host information when hostname/IP are enabled
type HostInfo struct {
	Name string `json:"name,omitempty"`
	IP   string `json:"ip,omitempty"`
}

// Event-specific structures that will be serialized to JSON
type ProcessJSON struct {
	Timestamp  string    `json:"timestamp"`
	SessionUID string    `json:"session_uid"`
	Host       *HostInfo `json:"host,omitempty"`
	EventType  string    `json:"event_type"`
	ProcessUID string    `json:"process_uid"`
	ParentUID  string    `json:"parent_uid,omitempty"`
	Process    struct {
		PID             uint32 `json:"pid"`
		Comm            string `json:"comm"`
		PPID            uint32 `json:"ppid"`
		ParentComm      string `json:"parent_comm"`
		UID             uint32 `json:"uid"`
		GID             uint32 `json:"gid"`
		ExePath         string `json:"exe_path"`
		BinaryHash      string `json:"binary_hash,omitempty"`
		CmdLine         string `json:"command_line"`
		Username        string `json:"username"`
		CWD             string `json:"cwd"`
		StartTime       string `json:"start_time,omitempty"`
		ExitTime        string `json:"exit_time,omitempty"`
		ExitCode        int32  `json:"exit_code,omitempty"`
		ExitDescription string `json:"exit_description,omitempty"`
		Duration        string `json:"duration,omitempty"`
	} `json:"process"`
	ContainerID string `json:"container_id,omitempty"`
	Message     string `json:"message,omitempty"`
}

type NetworkJSON struct {
	Timestamp   string    `json:"timestamp"`
	SessionUID  string    `json:"session_uid"`
	Host        *HostInfo `json:"host,omitempty"`
	EventType   string    `json:"event_type"`
	ProcessUID  string    `json:"process_uid"`
	NetworkUID  string    `json:"network_uid"`
	CommunityID string    `json:"community_id"`
	Process     struct {
		PID        uint32 `json:"pid"`
		Comm       string `json:"comm"`
		PPID       uint32 `json:"ppid"`
		ParentComm string `json:"parent_comm"`
	} `json:"process"`
	Network struct {
		Protocol      string `json:"protocol"`
		SourceIP      string `json:"source_ip"`
		SourcePort    uint16 `json:"source_port"`
		DestIP        string `json:"dest_ip"`
		DestPort      uint16 `json:"dest_port"`
		Direction     string `json:"direction"`
		DirectionDesc string `json:"direction_description,omitempty"`
		Bytes         uint32 `json:"bytes"`
		TCPFlags      string `json:"tcp_flags,omitempty"`
	} `json:"network"`
	Message string `json:"message,omitempty"`
}

type DNSJSON struct {
	Timestamp      string    `json:"timestamp"`
	SessionUID     string    `json:"session_uid"`
	Host           *HostInfo `json:"host,omitempty"`
	EventType      string    `json:"event_type"`
	ProcessUID     string    `json:"process_uid"`
	NetworkUID     string    `json:"network_uid"`
	CommunityID    string    `json:"community_id"`
	ConversationID string    `json:"dns_conversation_uid"`
	Process        struct {
		PID        uint32 `json:"pid"`
		Comm       string `json:"comm"`
		PPID       uint32 `json:"ppid"`
		ParentComm string `json:"parent_comm"`
	} `json:"process"`
	DNS struct {
		Type          string            `json:"type"` // "query" or "response"
		Flags         uint16            `json:"flags"`
		TransactionID uint16            `json:"transaction_id"`
		Questions     []DNSQuestionJSON `json:"questions,omitempty"`
		Answers       []DNSAnswerJSON   `json:"answers,omitempty"`
	} `json:"dns"`
	Network struct {
		SourceIP   string `json:"source_ip"`
		SourcePort uint16 `json:"source_port"`
		DestIP     string `json:"dest_ip"`
		DestPort   uint16 `json:"dest_port"`
	} `json:"network"`
	Message string `json:"message,omitempty"`
}

type DNSQuestionJSON struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class uint16 `json:"class"`
}

type DNSAnswerJSON struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Class uint16 `json:"class"`
	TTL   uint32 `json:"ttl"`
	Data  string `json:"data"`
}

type TLSJSON struct {
	Timestamp   string    `json:"timestamp"`
	SessionUID  string    `json:"session_uid"`
	Host        *HostInfo `json:"host,omitempty"`
	EventType   string    `json:"event_type"`
	ProcessUID  string    `json:"process_uid"`
	NetworkUID  string    `json:"network_uid"`
	CommunityID string    `json:"community_id"`
	Process     struct {
		PID        uint32 `json:"pid"`
		Comm       string `json:"comm"`
		PPID       uint32 `json:"ppid"`
		ParentComm string `json:"parent_comm"`
	} `json:"process"`
	TLS struct {
		Version         string   `json:"version"`
		SNI             string   `json:"sni,omitempty"`
		HandshakeType   uint8    `json:"handshake_type"`
		HandshakeLen    uint32   `json:"handshake_length"`
		CipherSuites    []string `json:"cipher_suites,omitempty"`
		SupportedGroups []string `json:"supported_groups,omitempty"`
		KeyShareGroups  []string `json:"key_share_groups,omitempty"`
		JA4             string   `json:"ja4,omitempty"`
		JA4Hash         string   `json:"ja4_hash,omitempty"`
	} `json:"tls"`
	Network struct {
		SourceIP   string `json:"source_ip"`
		SourcePort uint16 `json:"source_port"`
		DestIP     string `json:"dest_ip"`
		DestPort   uint16 `json:"dest_port"`
	} `json:"network"`
	Message string `json:"message,omitempty"`
}

type NetworkInfo struct {
	NetworkUID     string `json:"network_uid,omitempty"`
	ConversationID string `json:"dns_conversation_uid,omitempty"`
	CommunityID    string `json:"community_id,omitempty"`
	Protocol       string `json:"protocol,omitempty"`
	SourceIP       string `json:"source_ip,omitempty"`
	SourcePort     uint16 `json:"source_port,omitempty"`
	DestIP         string `json:"destination_ip,omitempty"`
	DestPort       uint16 `json:"destination_port,omitempty"`
	Direction      string `json:"direction,omitempty"`
	Hostname       string `json:"destination_hostname,omitempty"`
}

type SigmaMatchJSON struct {
	Timestamp     string    `json:"timestamp"`
	SessionUID    string    `json:"session_uid"`
	Host          *HostInfo `json:"host,omitempty"`
	EventType     string    `json:"event_type"`     // Will be "sigma_match"
	EventCategory string    `json:"event_category"` // "process" or "network"
	Rule          struct {
		ID           string   `json:"id"`
		Name         string   `json:"name"`
		Level        string   `json:"level"`
		Description  string   `json:"description"`
		MatchDetails string   `json:"match_details"` // Human readable match conditions
		References   []string `json:"references"`
		Tags         []string `json:"tags"`
	} `json:"rule"`
	Process struct {
		UID         string   `json:"process_uid"`
		PID         uint32   `json:"pid"`
		Name        string   `json:"name"`
		ExePath     string   `json:"exe_path"`
		CmdLine     string   `json:"command_line"`
		WorkingDir  string   `json:"working_directory"`
		Username    string   `json:"username,omitempty"`
		StartTime   string   `json:"start_time,omitempty"`
		BinaryHash  string   `json:"binary_hash,omitempty"`
		Environment []string `json:"environment,omitempty"`
	} `json:"process"`
	ParentProcess struct {
		UID        string `json:"process_uid,omitempty"`
		PID        uint32 `json:"pid,omitempty"`
		Name       string `json:"name,omitempty"`
		ExePath    string `json:"exe_path,omitempty"`
		CmdLine    string `json:"command_line,omitempty"`
		Username   string `json:"username,omitempty"`
		StartTime  string `json:"start_time,omitempty"`
		BinaryHash string `json:"binary_hash,omitempty"`
	} `json:"parent_process,omitempty"`
	Network         *NetworkInfo `json:"network,omitempty"`
	Message         string       `json:"message"`
	DetectionSource string       `json:"detection_source"`
	Labels          struct {
		SessionUID     string `json:"session_uid"`
		ProcessUID     string `json:"process_uid"`
		ParentUID      string `json:"parent_uid,omitempty"`
		NetworkUID     string `json:"network_uid,omitempty"`
		ConversationID string `json:"dns_conversation_uid,omitempty"`
		CommunityID    string `json:"community_id,omitempty"`
	} `json:"labels"`
}

func NewJSONFormatter(output io.Writer, hostname, hostIP, sessionUID string, enableSigma bool) *JSONFormatter {
	f := &JSONFormatter{
		output:       output,
		hostname:     hostname,
		hostIP:       hostIP,
		sessionUID:   sessionUID,
		sigmaEnabled: enableSigma,
		encoder:      json.NewEncoder(output),
	}
	f.encoder.SetEscapeHTML(false)
	return f
}

func (f *JSONFormatter) Initialize() error {
	return nil
}

func (f *JSONFormatter) Close() error {
	return nil
}

func (f *JSONFormatter) FormatProcess(event *types.ProcessEvent, info *types.ProcessInfo, parentinfo *types.ProcessInfo) error {
	jsonEvent := ProcessJSON{
		Timestamp:  BpfTimestampToTime(event.Timestamp).UTC().Format(time.RFC3339Nano),
		SessionUID: f.sessionUID,
		EventType:  eventTypeString(event.EventType),
		ProcessUID: info.ProcessUID,
	}

	// Add host info if enabled
	if f.hostname != "" || f.hostIP != "" {
		jsonEvent.Host = &HostInfo{
			Name: f.hostname,
			IP:   f.hostIP,
		}
	}

	// Fill process information
	jsonEvent.Process.PID = info.PID
	jsonEvent.Process.Comm = info.Comm
	jsonEvent.Process.PPID = info.PPID
	parentComm := string(bytes.TrimRight(event.ParentComm[:], "\x00"))
	jsonEvent.Process.ParentComm = parentComm
	jsonEvent.Process.UID = info.UID
	jsonEvent.Process.GID = info.GID
	jsonEvent.Process.ExePath = info.ExePath
	jsonEvent.Process.BinaryHash = info.BinaryHash
	jsonEvent.Process.CmdLine = info.CmdLine
	jsonEvent.Process.Username = info.Username
	jsonEvent.Process.CWD = info.WorkingDir

	if !info.StartTime.IsZero() {
		jsonEvent.Process.StartTime = info.StartTime.Format(time.RFC3339Nano)
	}

	if !info.ExitTime.IsZero() {
		jsonEvent.Process.ExitTime = info.ExitTime.Format(time.RFC3339Nano)
		jsonEvent.Process.ExitCode = int32(info.ExitCode)

		switch info.ExitCode {
		case 0:
			jsonEvent.Process.ExitDescription = "Success"
		case 1:
			jsonEvent.Process.ExitDescription = "General error"
		case 126:
			jsonEvent.Process.ExitDescription = "Command not executable"
		case 127:
			jsonEvent.Process.ExitDescription = "Command not found"
		case 130:
			jsonEvent.Process.ExitDescription = "Terminated by Ctrl+C"
		case 255:
			jsonEvent.Process.ExitDescription = "Exit status out of range or SSH closed"
		}

		if !info.StartTime.IsZero() {
			jsonEvent.Process.Duration = info.ExitTime.Sub(info.StartTime).String()
		}
	}

	if parentinfo != nil && parentinfo.ProcessUID != "" {
		jsonEvent.ParentUID = parentinfo.ProcessUID
	}

	if event.EventType == types.EVENT_PROCESS_EXEC {
		jsonEvent.Message = fmt.Sprintf("process_exec: %s (PID: %d)", info.Comm, info.PID)
	} else if event.EventType == types.EVENT_PROCESS_FORK {
		jsonEvent.Message = fmt.Sprintf("process_fork: %s (PID: %d)", info.Comm, info.PID)
	} else {
		jsonEvent.Message = fmt.Sprintf("process_exit: %s (PID: %d)", info.Comm, info.PID)
	}

	jsonEvent.ContainerID = info.ContainerID

	return f.encoder.Encode(jsonEvent)
}

func (f *JSONFormatter) FormatNetwork(event *types.NetworkEvent, info *types.ProcessInfo) error {
	jsonEvent := NetworkJSON{
		Timestamp:  BpfTimestampToTime(event.Timestamp).UTC().Format(time.RFC3339Nano),
		SessionUID: f.sessionUID,
		EventType:  "network_flow",
		ProcessUID: info.ProcessUID,
	}

	if f.hostname != "" || f.hostIP != "" {
		jsonEvent.Host = &HostInfo{
			Name: f.hostname,
			IP:   f.hostIP,
		}
	}

	jsonEvent.NetworkUID = GenerateBidirectionalConnID(event.Pid, event.Ppid,
		uint32ToNetIP(event.SrcIP),
		uint32ToNetIP(event.DstIP),
		event.SrcPort, event.DstPort)
	jsonEvent.CommunityID = GenerateCommunityID(
		uint32ToNetIP(event.SrcIP),
		uint32ToNetIP(event.DstIP),
		event.SrcPort,
		event.DstPort,
		event.Protocol,
		0) // default seed

	// Fill process info
	jsonEvent.Process.PID = event.Pid
	jsonEvent.Process.Comm = string(bytes.TrimRight(event.Comm[:], "\x00"))
	jsonEvent.Process.PPID = event.Ppid
	parentComm := string(bytes.TrimRight(event.ParentComm[:], "\x00"))
	jsonEvent.Process.ParentComm = parentComm

	// Fill network info
	jsonEvent.Network.Protocol = protocolToString(event.Protocol)
	jsonEvent.Network.SourceIP = ipToString(event.SrcIP)
	jsonEvent.Network.SourcePort = event.SrcPort
	jsonEvent.Network.DestIP = ipToString(event.DstIP)
	jsonEvent.Network.DestPort = event.DstPort
	jsonEvent.Network.Bytes = event.BytesCount
	if event.Protocol == 6 { // TCP
		jsonEvent.Network.TCPFlags = FormatTCPFlags(event.TCPFlags)
	}

	if event.Direction == types.FLOW_INGRESS {
		jsonEvent.Network.Direction = "ingress"
		jsonEvent.Network.DirectionDesc = "Incoming traffic from external host"
	} else {
		jsonEvent.Network.Direction = "egress"
		jsonEvent.Network.DirectionDesc = "Outgoing traffic to external service"
	}

	jsonEvent.Message = fmt.Sprintf("Network connection: %s:%d → %s:%d (%s)",
		jsonEvent.Network.SourceIP, jsonEvent.Network.SourcePort,
		jsonEvent.Network.DestIP, jsonEvent.Network.DestPort,
		strings.ToLower(jsonEvent.Network.Protocol))

	return f.encoder.Encode(jsonEvent)
}

func (f *JSONFormatter) FormatDNS(event *types.UserSpaceDNSEvent, info *types.ProcessInfo) error {
	eventType := "dns_query"
	if event.IsResponse {
		eventType = "dns_response"
	}

	jsonEvent := DNSJSON{
		Timestamp:      BpfTimestampToTime(event.Timestamp).UTC().Format(time.RFC3339Nano),
		SessionUID:     f.sessionUID,
		EventType:      eventType,
		ConversationID: event.ConversationID,
		ProcessUID:     info.ProcessUID,
	}

	if f.hostname != "" || f.hostIP != "" {
		jsonEvent.Host = &HostInfo{
			Name: f.hostname,
			IP:   f.hostIP,
		}
	}

	// Generate network_uid
	jsonEvent.NetworkUID = GenerateBidirectionalConnID(event.Pid, event.Ppid,
		event.SourceIP, event.DestIP,
		event.SourcePort, event.DestPort)
	jsonEvent.CommunityID = GenerateCommunityID(
		event.SourceIP,
		event.DestIP,
		event.SourcePort,
		event.DestPort,
		17, // UDP
		0)  // default seed

	// Process info
	jsonEvent.Process.PID = event.Pid
	jsonEvent.Process.Comm = event.Comm
	jsonEvent.Process.PPID = event.Ppid
	parentComm := strings.TrimRight(string(event.ParentComm[:]), "\x00")
	jsonEvent.Process.ParentComm = parentComm

	// DNS info
	jsonEvent.DNS.Type = "query"
	if event.IsResponse {
		jsonEvent.DNS.Type = "response"
	}
	jsonEvent.DNS.Flags = event.DNSFlags
	jsonEvent.DNS.TransactionID = event.TransactionID

	// Questions
	for _, q := range event.Questions {
		jsonEvent.DNS.Questions = append(jsonEvent.DNS.Questions, DNSQuestionJSON{
			Name:  q.Name,
			Type:  dnsTypeToString(q.Type),
			Class: q.Class,
		})
	}

	// Answers (for responses)
	if event.IsResponse {
		for _, a := range event.Answers {
			answer := DNSAnswerJSON{
				Name:  a.Name,
				Type:  dnsTypeToString(a.Type),
				Class: a.Class,
				TTL:   a.TTL,
			}

			// Format answer data based on type
			switch a.Type {
			case 1, 28: // A or AAAA
				if a.IPAddress != nil {
					answer.Data = a.IPAddress.String()
				}
			case 5: // CNAME
				answer.Data = a.CName
			default:
				answer.Data = fmt.Sprintf("%s record", dnsTypeToString(a.Type))
			}

			jsonEvent.DNS.Answers = append(jsonEvent.DNS.Answers, answer)
		}

		if len(event.Questions) > 0 {
			jsonEvent.Message = fmt.Sprintf("DNS response: %s", event.Questions[0].Name)
		} else {
			jsonEvent.Message = "DNS response"
		}
	} else {
		if len(event.Questions) > 0 {
			jsonEvent.Message = fmt.Sprintf("DNS query: %s", event.Questions[0].Name)
		} else {
			jsonEvent.Message = "DNS query"
		}
	}

	// Network info
	jsonEvent.Network.SourceIP = event.SourceIP.String()
	jsonEvent.Network.SourcePort = event.SourcePort
	jsonEvent.Network.DestIP = event.DestIP.String()
	jsonEvent.Network.DestPort = event.DestPort

	return f.encoder.Encode(jsonEvent)
}

func (f *JSONFormatter) FormatTLS(event *types.UserSpaceTLSEvent, info *types.ProcessInfo) error {
	jsonEvent := TLSJSON{
		Timestamp:  BpfTimestampToTime(event.Timestamp).UTC().Format(time.RFC3339Nano),
		SessionUID: f.sessionUID,
		EventType:  "tls_handshake",
		ProcessUID: info.ProcessUID,
	}

	if f.hostname != "" || f.hostIP != "" {
		jsonEvent.Host = &HostInfo{
			Name: f.hostname,
			IP:   f.hostIP,
		}
	}

	// Generate network_uid
	jsonEvent.NetworkUID = GenerateBidirectionalConnID(event.Pid, event.Ppid,
		event.SourceIP, event.DestIP,
		event.SourcePort, event.DestPort)
	jsonEvent.CommunityID = GenerateCommunityID(
		event.SourceIP,
		event.DestIP,
		event.SourcePort,
		event.DestPort,
		event.Protocol,
		0) // default seed

	// Process info
	jsonEvent.Process.PID = event.Pid
	jsonEvent.Process.Comm = event.Comm
	jsonEvent.Process.PPID = event.Ppid
	parentComm := strings.TrimRight(string(event.ParentComm[:]), "\x00")
	jsonEvent.Process.ParentComm = parentComm

	// TLS info
	jsonEvent.TLS.Version = formatTlsVersion(event.TLSVersion)
	jsonEvent.TLS.SNI = event.SNI
	jsonEvent.TLS.HandshakeType = event.HandshakeType
	jsonEvent.TLS.HandshakeLen = event.HandshakeLength

	// Convert cipher suites to strings
	for _, cs := range event.CipherSuites {
		jsonEvent.TLS.CipherSuites = append(jsonEvent.TLS.CipherSuites,
			fmt.Sprintf("0x%04x", cs))
	}

	// Convert supported groups to strings
	for _, group := range event.SupportedGroups {
		jsonEvent.TLS.SupportedGroups = append(jsonEvent.TLS.SupportedGroups,
			formatSupportedGroup(group))
	}

	// Convert key share groups to strings
	for _, group := range event.KeyShareGroups {
		jsonEvent.TLS.KeyShareGroups = append(jsonEvent.TLS.KeyShareGroups,
			formatSupportedGroup(group))
	}

	// JA4 fingerprinting
	if event.JA4 != "" {
		jsonEvent.TLS.JA4 = event.JA4
		jsonEvent.TLS.JA4Hash = event.JA4Hash
	}

	if event.SNI != "" {
		jsonEvent.Message = fmt.Sprintf("TLS handshake: %s (%s)", event.SNI, formatTlsVersion(event.TLSVersion))
	} else {
		jsonEvent.Message = fmt.Sprintf("TLS handshake: %s", formatTlsVersion(event.TLSVersion))
	}

	// Network info
	jsonEvent.Network.SourceIP = event.SourceIP.String()
	jsonEvent.Network.SourcePort = event.SourcePort
	jsonEvent.Network.DestIP = event.DestIP.String()
	jsonEvent.Network.DestPort = event.DestPort

	return f.encoder.Encode(jsonEvent)
}

func (f *JSONFormatter) FormatSigmaMatch(match *types.SigmaMatch) error {
	jsonEvent := SigmaMatchJSON{
		Timestamp:       match.Timestamp.UTC().Format(time.RFC3339Nano),
		SessionUID:      f.sessionUID,
		EventType:       "sigma_match",
		DetectionSource: match.DetectionSource,
	}

	// Set event category based on detection source
	switch match.DetectionSource {
	case "process_creation":
		jsonEvent.EventCategory = "process"
	case "network_connection", "dns_query":
		jsonEvent.EventCategory = "network"
	}

	// Add host info if enabled
	if f.hostname != "" || f.hostIP != "" {
		jsonEvent.Host = &HostInfo{
			Name: f.hostname,
			IP:   f.hostIP,
		}
	}

	// Fill rule information
	jsonEvent.Rule.ID = match.RuleID
	jsonEvent.Rule.Name = match.RuleName
	jsonEvent.Rule.Level = match.RuleLevel
	jsonEvent.Rule.Description = match.RuleDescription
	if details, ok := match.MatchedFields["details"].(string); ok {
		jsonEvent.Rule.MatchDetails = details
	}
	jsonEvent.Rule.References = match.RuleReferences
	jsonEvent.Rule.Tags = match.RuleTags

	// Add process context
	jsonEvent.Process.UID = match.ProcessUID
	jsonEvent.Process.PID = match.PID

	if match.ProcessInfo != nil {
		jsonEvent.Process.Name = match.ProcessInfo.Comm
		jsonEvent.Process.ExePath = match.ProcessInfo.ExePath
		jsonEvent.Process.CmdLine = match.ProcessInfo.CmdLine
		jsonEvent.Process.WorkingDir = match.ProcessInfo.WorkingDir
		jsonEvent.Process.Username = match.ProcessInfo.Username
		jsonEvent.Process.BinaryHash = match.ProcessInfo.BinaryHash
		jsonEvent.Process.Environment = match.ProcessInfo.Environment

		if !match.ProcessInfo.StartTime.IsZero() {
			jsonEvent.Process.StartTime = match.ProcessInfo.StartTime.UTC().Format(time.RFC3339Nano)
		}
	}

	// Parent process information
	if match.ParentInfo != nil {
		jsonEvent.ParentProcess.UID = match.ParentInfo.ProcessUID
		jsonEvent.ParentProcess.PID = match.ParentInfo.PID
		jsonEvent.ParentProcess.Name = match.ParentInfo.Comm
		jsonEvent.ParentProcess.ExePath = match.ParentInfo.ExePath
		jsonEvent.ParentProcess.CmdLine = match.ParentInfo.CmdLine
		jsonEvent.ParentProcess.Username = match.ParentInfo.Username
		jsonEvent.ParentProcess.BinaryHash = match.ParentInfo.BinaryHash

		if !match.ParentInfo.StartTime.IsZero() {
			jsonEvent.ParentProcess.StartTime = match.ParentInfo.StartTime.UTC().Format(time.RFC3339Nano)
		}

	}

	// Add network correlation for network-related detections
	// Network information for network-related detections
	if match.DetectionSource == "dns_query" || match.DetectionSource == "network_connection" {
		networkInfo := &NetworkInfo{}

		// Core correlation IDs
		networkInfo.NetworkUID = match.NetworkUID
		networkInfo.CommunityID = match.CommunityID
		if match.ConversationID != "" {
			networkInfo.ConversationID = match.ConversationID
		}

		// Network details
		if srcIP, ok := match.EventData["SourceIp"].(string); ok {
			networkInfo.SourceIP = srcIP
		}
		if srcPort, ok := match.EventData["SourcePort"].(uint16); ok {
			networkInfo.SourcePort = srcPort
		}
		if dstIP, ok := match.EventData["DestinationIp"].(string); ok {
			networkInfo.DestIP = dstIP
		}
		if dstPort, ok := match.EventData["DestinationPort"].(uint16); ok {
			networkInfo.DestPort = dstPort
		}
		if protocol, ok := match.EventData["Protocol"].(string); ok {
			networkInfo.Protocol = protocol
		}
		if direction, ok := match.EventData["Direction"].(string); ok {
			networkInfo.Direction = direction
		}

		// DNS specific fields
		if hostname, ok := match.EventData["DestinationHostname"].(string); ok {
			networkInfo.Hostname = hostname
		}

		jsonEvent.Network = networkInfo
	}

	// Create descriptive message
	jsonEvent.Message = fmt.Sprintf("Sigma rule match: %s (Level: %s)",
		match.RuleName, match.RuleLevel)
	if match.ProcessInfo != nil {
		jsonEvent.Message += fmt.Sprintf(" - Process: %s [%d]",
			match.ProcessInfo.Comm, match.PID)
	}

	jsonEvent.Labels.SessionUID = f.sessionUID
	jsonEvent.Labels.ProcessUID = match.ProcessUID
	if match.ParentInfo != nil && match.ParentInfo.ProcessUID != "" {
		jsonEvent.Labels.ParentUID = match.ParentInfo.ProcessUID
	}
	if match.DetectionSource == "network_connection" || match.DetectionSource == "dns_query" {
		jsonEvent.Labels.NetworkUID = match.NetworkUID
		jsonEvent.Labels.CommunityID = match.CommunityID
		if match.ConversationID != "" {
			jsonEvent.Labels.ConversationID = match.ConversationID
		}
	}

	return f.encoder.Encode(jsonEvent)
}
