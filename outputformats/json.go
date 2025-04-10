package outputformats

import (
	"bytes"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"io"
	"strings"
	"time"

	"github.com/jnesss/bpfview/types"
)

type JSONFormatter struct {
	encoder    *json.Encoder
	output     io.Writer
	hostname   string
	hostIP     string
	sessionUID string
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
	Process    struct {
		PID        uint32 `json:"pid"`
		Comm       string `json:"comm"`
		PPID       uint32 `json:"ppid"`
		ParentComm string `json:"parent_comm"`
		UID        uint32 `json:"uid"`
		GID        uint32 `json:"gid"`
		ExePath    string `json:"exe_path"`
		BinaryHash string `json:"binary_hash,omitempty"`
		CmdLine    string `json:"cmdline"`
		Username   string `json:"username"`
		CWD        string `json:"cwd"`
		StartTime  string `json:"start_time,omitempty"`
		ExitTime   string `json:"exit_time,omitempty"`
		ExitCode   int32  `json:"exit_code,omitempty"`
		Duration   string `json:"duration,omitempty"`
	} `json:"process"`
	ContainerID string `json:"container_id,omitempty"`
}

type NetworkJSON struct {
	Timestamp  string    `json:"timestamp"`
	SessionUID string    `json:"session_uid"`
	Host       *HostInfo `json:"host,omitempty"`
	EventType  string    `json:"event_type"` // Add this
	ProcessUID string    `json:"process_uid"`
	NetworkUID string    `json:"network_uid"`
	Process    struct {
		PID        uint32 `json:"pid"`
		Comm       string `json:"comm"`
		PPID       uint32 `json:"ppid"`
		ParentComm string `json:"parent_comm"`
	} `json:"process"`
	Network struct {
		Protocol   string `json:"protocol"`
		SourceIP   string `json:"source_ip"`
		SourcePort uint16 `json:"source_port"`
		DestIP     string `json:"dest_ip"`
		DestPort   uint16 `json:"dest_port"`
		Direction  string `json:"direction"`
		Bytes      uint32 `json:"bytes"`
	} `json:"network"`
}

type DNSJSON struct {
	Timestamp      string    `json:"timestamp"`
	SessionUID     string    `json:"session_uid"`
	Host           *HostInfo `json:"host,omitempty"`
	EventType      string    `json:"event_type"`
	ProcessUID     string    `json:"process_uid"`
	NetworkUID     string    `json:"network_uid"`
	ConversationID string    `json:"conversation_id"`
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
	Timestamp  string    `json:"timestamp"`
	SessionUID string    `json:"session_uid"`
	Host       *HostInfo `json:"host,omitempty"`
	EventType  string    `json:"event_type"`
	ProcessUID string    `json:"process_uid"`
	NetworkUID string    `json:"network_uid"`
	Process    struct {
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
}

func NewJSONFormatter(output io.Writer, hostname, hostIP, sessionUID string) *JSONFormatter {
	f := &JSONFormatter{
		output:     output,
		hostname:   hostname,
		hostIP:     hostIP,
		sessionUID: sessionUID,
		encoder:    json.NewEncoder(output),
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

func (f *JSONFormatter) FormatProcess(event *types.ProcessEvent, info *types.ProcessInfo) error {
	jsonEvent := ProcessJSON{
		Timestamp:  BpfTimestampToTime(event.Timestamp).UTC().Format(time.RFC3339Nano),
		SessionUID: f.sessionUID,
		EventType:  eventTypeString(event.EventType),
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

		if !info.StartTime.IsZero() {
			jsonEvent.Process.Duration = info.ExitTime.Sub(info.StartTime).String()
		}
	}

	jsonEvent.ContainerID = info.ContainerID

	return f.encoder.Encode(jsonEvent)
}

func (f *JSONFormatter) FormatNetwork(event *types.NetworkEvent, info *types.ProcessInfo) error {
	jsonEvent := NetworkJSON{
		Timestamp:  BpfTimestampToTime(event.Timestamp).UTC().Format(time.RFC3339Nano),
		SessionUID: f.sessionUID,
		EventType:  "network_flow",
	}

	if f.hostname != "" || f.hostIP != "" {
		jsonEvent.Host = &HostInfo{
			Name: f.hostname,
			IP:   f.hostIP,
		}
	}

	// Generate UIDs for correlation
	h := fnv.New32a()
	process_start_str := info.StartTime.Format(time.RFC3339Nano)
	h.Write([]byte(fmt.Sprintf("%s-%d", process_start_str, event.Pid)))
	if info.ExePath != "" {
		h.Write([]byte(info.ExePath))
	}
	jsonEvent.ProcessUID = fmt.Sprintf("%x", h.Sum32())

	jsonEvent.NetworkUID = generateConnID(event.Pid, event.Ppid,
		uint32ToNetIP(event.SrcIP),
		uint32ToNetIP(event.DstIP),
		event.SrcPort, event.DstPort)

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
	jsonEvent.Network.Direction = directionToString(event.Direction)
	jsonEvent.Network.Bytes = event.BytesCount

	return f.encoder.Encode(jsonEvent)
}

func directionToString(direction uint8) string {
	if direction == types.FLOW_INGRESS {
		return "ingress"
	}
	return "egress"
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
	}

	if f.hostname != "" || f.hostIP != "" {
		jsonEvent.Host = &HostInfo{
			Name: f.hostname,
			IP:   f.hostIP,
		}
	}

	// Calculate process_uid
	h := fnv.New32a()
	process_start_str := info.StartTime.Format(time.RFC3339Nano)
	h.Write([]byte(fmt.Sprintf("%s-%d", process_start_str, event.Pid)))
	if info.ExePath != "" {
		h.Write([]byte(info.ExePath))
	}
	jsonEvent.ProcessUID = fmt.Sprintf("%x", h.Sum32())

	// Generate network_uid
	jsonEvent.NetworkUID = generateConnID(event.Pid, event.Ppid,
		event.SourceIP, event.DestIP,
		event.SourcePort, event.DestPort)

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
	}

	if f.hostname != "" || f.hostIP != "" {
		jsonEvent.Host = &HostInfo{
			Name: f.hostname,
			IP:   f.hostIP,
		}
	}

	// Calculate process_uid
	h := fnv.New32a()
	process_start_str := info.StartTime.Format(time.RFC3339Nano)
	h.Write([]byte(fmt.Sprintf("%s-%d", process_start_str, event.Pid)))
	if info.ExePath != "" {
		h.Write([]byte(info.ExePath))
	}
	jsonEvent.ProcessUID = fmt.Sprintf("%x", h.Sum32())

	// Generate network_uid
	jsonEvent.NetworkUID = generateConnID(event.Pid, event.Ppid,
		event.SourceIP, event.DestIP,
		event.SourcePort, event.DestPort)

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

	// Network info
	jsonEvent.Network.SourceIP = event.SourceIP.String()
	jsonEvent.Network.SourcePort = event.SourcePort
	jsonEvent.Network.DestIP = event.DestIP.String()
	jsonEvent.Network.DestPort = event.DestPort

	return f.encoder.Encode(jsonEvent)
}
