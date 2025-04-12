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
	encoder    *json.Encoder
	output     io.Writer
	hostname   string
	hostIP     string
	sessionUID string
}

// ECS base event structure
type ecsEvent struct {
	// ECS base fields
	Timestamp string `json:"@timestamp"`
	Version   string `json:"ecs.version"`    // ECS version
	Type      string `json:"event.type"`     // e.g., process, network, dns
	Category  string `json:"event.category"` // e.g., process, network
	Kind      string `json:"event.kind"`     // e.g., event, alert, metric
	Dataset   string `json:"event.dataset"`  // Source of the event (bpfview)
	Sequence  string `json:"event.sequence"` // Session UID
	Action    string `json:"event.action"`   // Specific action being taken
	Outcome   string `json:"event.outcome"`  // success, failure, unknown
	Message   string `json:"message,omitempty"`

	// Host information
	HostName    string `json:"host.name,omitempty"`
	HostIP      string `json:"host.ip,omitempty"`
	HostOS      string `json:"host.os.type"`
	HostKernel  string `json:"host.os.kernel"`
	HostVersion string `json:"host.os.version,omitempty"`

	// Process information
	ProcessName     string   `json:"process.name,omitempty"`
	ProcessPID      int64    `json:"process.pid,omitempty"`
	ProcessTID      int64    `json:"process.thread.id,omitempty"`
	ProcessArgs     []string `json:"process.args,omitempty"`
	ProcessCwd      string   `json:"process.working_directory,omitempty"`
	ProcessExe      string   `json:"process.executable,omitempty"`
	ProcessHash     string   `json:"process.hash.md5,omitempty"`
	ProcessCommand  string   `json:"process.command_line,omitempty"`
	ProcessEnv      []string `json:"process.env,omitempty"`
	ProcessStart    string   `json:"process.start,omitempty"`
	ProcessEnd      string   `json:"process.end,omitempty"`
	ProcessExitCode int64    `json:"process.exit_code,omitempty"`
	ExitDescription string   `json:"process.exit_description,omitempty"`
	ProcessDuration string   `json:"process.duration,omitempty"`

	// Parent process
	ParentProcessName string `json:"process.parent.name,omitempty"`
	ParentProcessPID  int64  `json:"process.parent.pid,omitempty"`

	// User information
	UserID   string `json:"user.id,omitempty"`
	UserName string `json:"user.name,omitempty"`
	GroupID  string `json:"user.group.id,omitempty"`

	// Container information
	ContainerID string `json:"container.id,omitempty"`

	// Network information
	NetworkType      string `json:"network.type,omitempty"`
	NetworkProtocol  string `json:"network.protocol,omitempty"`
	NetworkBytes     int64  `json:"network.bytes,omitempty"`
	NetworkDirection string `json:"network.direction,omitempty"`
	DirectionDesc    string `json:"network.direction_description,omitempty"`

	// Source/Destination
	SourceIP        string `json:"source.ip,omitempty"`
	SourcePort      int64  `json:"source.port,omitempty"`
	DestinationIP   string `json:"destination.ip,omitempty"`
	DestinationPort int64  `json:"destination.port,omitempty"`

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

	// Custom fields for correlation
	Labels map[string]string `json:"labels,omitempty"`
}

func NewECSFormatter(output io.Writer, hostname, hostIP, sessionUID string) *ECSFormatter {
	f := &ECSFormatter{
		output:     output,
		encoder:    json.NewEncoder(output),
		hostname:   hostname,
		hostIP:     hostIP,
		sessionUID: sessionUID,
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

func (f *ECSFormatter) FormatProcess(event *types.ProcessEvent, info *types.ProcessInfo) error {
	ecsEvent := f.createBaseEvent()
	ecsEvent.Type = "process"
	ecsEvent.Category = "process"
	ecsEvent.Kind = "event"

	// Set process action based on event type
	if event.EventType == types.EVENT_PROCESS_EXEC {
		ecsEvent.Action = "process_started"
		ecsEvent.Outcome = "success"
		ecsEvent.Message = fmt.Sprintf("process_exec: %s (PID: %d)", info.Comm, info.PID)
	} else {
		ecsEvent.Action = "process_stopped"
		ecsEvent.Outcome = fmt.Sprintf("exit_code_%d", info.ExitCode)
		ecsEvent.Message = fmt.Sprintf("process_exit: %s (PID: %d)", info.Comm, info.PID)
	}

	// Process information
	ecsEvent.ProcessName = info.Comm
	ecsEvent.ProcessPID = int64(info.PID)
	ecsEvent.ProcessExe = info.ExePath
	ecsEvent.ProcessCwd = info.WorkingDir
	ecsEvent.ProcessHash = info.BinaryHash
	ecsEvent.ProcessCommand = info.CmdLine

	// Split command line into args if present
	if info.CmdLine != "" {
		ecsEvent.ProcessArgs = strings.Fields(info.CmdLine)
	}

	// Parent process
	ecsEvent.ParentProcessPID = int64(info.PPID)
	parentComm := string(bytes.TrimRight(event.ParentComm[:], "\x00"))
	ecsEvent.ParentProcessName = parentComm

	// User information
	ecsEvent.UserID = fmt.Sprintf("%d", info.UID)
	ecsEvent.UserName = info.Username
	ecsEvent.GroupID = fmt.Sprintf("%d", info.GID)

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

		// Add exit code description for common codes
		switch info.ExitCode {
		case 0:
			ecsEvent.ExitDescription = "Success"
		case 1:
			ecsEvent.ExitDescription = "General error"
		case 126:
			ecsEvent.ExitDescription = "Command not executable"
		case 127:
			ecsEvent.ExitDescription = "Command not found"
		case 130:
			ecsEvent.ExitDescription = "Terminated by Ctrl+C"
		case 255:
			ecsEvent.ExitDescription = "Exit status out of range or SSH closed"
		}

		if !info.StartTime.IsZero() {
			ecsEvent.ProcessDuration = info.ExitTime.Sub(info.StartTime).String()
		}
	}

	// Add correlation IDs in labels
	ecsEvent.Labels = map[string]string{
		"session_uid": f.sessionUID,
		"process_uid": generateProcessUID(info),
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
		ecsEvent.DirectionDesc = "Incoming traffic from external host"
	} else {
		ecsEvent.NetworkDirection = "egress"
		ecsEvent.DirectionDesc = "Outgoing traffic to external service"
	}

	// Source and destination
	ecsEvent.SourceIP = ipToString(event.SrcIP)
	ecsEvent.SourcePort = int64(event.SrcPort)
	ecsEvent.DestinationIP = ipToString(event.DstIP)
	ecsEvent.DestinationPort = int64(event.DstPort)

	// Process information
	ecsEvent.ProcessName = string(bytes.TrimRight(event.Comm[:], "\x00"))
	ecsEvent.ProcessPID = int64(event.Pid)
	ecsEvent.ParentProcessName = string(bytes.TrimRight(event.ParentComm[:], "\x00"))
	ecsEvent.ParentProcessPID = int64(event.Ppid)

	ecsEvent.Message = fmt.Sprintf("Network connection: %s:%d → %s:%d (%s)",
		ecsEvent.SourceIP, ecsEvent.SourcePort,
		ecsEvent.DestinationIP, ecsEvent.DestinationPort,
		ecsEvent.NetworkProtocol)

	// Add correlation IDs in labels
	ecsEvent.Labels = map[string]string{
		"session_uid": f.sessionUID,
		"process_uid": generateProcessUID(info),
		"network_uid": generateConnID(event.Pid, event.Ppid,
			uint32ToNetIP(event.SrcIP),
			uint32ToNetIP(event.DstIP),
			event.SrcPort, event.DstPort),
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
		"session_uid":     f.sessionUID,
		"process_uid":     generateProcessUID(info),
		"network_uid":     generateConnID(event.Pid, event.Ppid, event.SourceIP, event.DestIP, event.SourcePort, event.DestPort),
		"conversation_id": event.ConversationID,
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
		"process_uid": generateProcessUID(info),
		"network_uid": generateConnID(event.Pid, event.Ppid, event.SourceIP, event.DestIP, event.SourcePort, event.DestPort),
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
