package main

import (
	"net"
)

// Event type constants
const (
	EVENT_PROCESS_EXEC = 1
	EVENT_PROCESS_EXIT = 2
	EVENT_NET_CONNECT  = 3
	EVENT_NET_ACCEPT   = 4
	EVENT_NET_BIND     = 5
	EVENT_DNS          = 6
	EVENT_TLS          = 7
)

// Flow direction constants matching BPF program
const (
	FLOW_INGRESS = 1
	FLOW_EGRESS  = 2
)

// ProcessEvent represents a process execution or exit event
type ProcessEvent struct {
	EventType  uint32
	Pid        uint32
	Timestamp  uint64
	Comm       [16]byte
	Ppid       uint32
	Uid        uint32
	Gid        uint32
	ExitCode   uint32
	ParentComm [16]byte
	ExePath    [64]byte
	Flags      uint32
	_          uint32 // padding
}

// NetworkEvent represents a network connection event
type NetworkEvent struct {
	EventType  uint32
	Pid        uint32
	Ppid       uint32
	Timestamp  uint64
	Comm       [16]byte
	ParentComm [16]byte
	SrcIP      uint32
	DstIP      uint32
	SrcPort    uint16
	DstPort    uint16
	Protocol   uint8
	Direction  uint8
	BytesCount uint32
	_          uint32 // padding for 8-byte alignment
}

// DNS event structures
type DNSQuestion struct {
	Name  string
	Type  uint16
	Class uint16
}

type DNSAnswer struct {
	Name      string
	Type      uint16
	Class     uint16
	TTL       uint32
	DataLen   uint16
	IPAddress net.IP // For A/AAAA records
	CName     string // For CNAME records
	Data      []byte // For other types
}

// BPFDNSRawEvent represents the raw event structure from kernel
type BPFDNSRawEvent struct {
	EventType  uint32
	Pid        uint32
	Ppid       uint32
	Timestamp  uint64
	Comm       [16]byte
	ParentComm [16]byte
	SrcAddr    uint32
	DstAddr    uint32
	SPort      uint16
	DPort      uint16
	IsResponse uint8
	DNSFlags   uint16
	DataLen    uint16
	Data       [512]byte
}

// UserSpaceDNSEvent represents parsed DNS data
type UserSpaceDNSEvent struct {
	// Process context
	Pid        uint32
	Ppid       uint32
	Timestamp  uint64
	Comm       string
	ParentComm string

	// Connection info
	SourceIP   net.IP
	DestIP     net.IP
	SourcePort uint16
	DestPort   uint16
	IsResponse bool

	// DNS fields
	ConversationID string
	DNSFlags       uint16
	TransactionID  uint16
	Questions      []DNSQuestion
	Answers        []DNSAnswer
}

// TLS event structures
type BPFTLSEvent struct {
	EventType       uint32
	Pid             uint32
	Ppid            uint32
	Timestamp       uint64
	Comm            [16]byte
	ParentComm      [16]byte
	Version         uint32
	HandshakeLength uint32
	// IP address components
	SAddrA uint8
	SAddrB uint8
	SAddrC uint8
	SAddrD uint8
	DAddrA uint8
	DAddrB uint8
	DAddrC uint8
	DAddrD uint8
	SPort  uint16
	DPort  uint16
	// Raw data
	DataLen uint16
	Data    [512]byte
}

// UserSpaceTLSEvent represents parsed TLS data
type UserSpaceTLSEvent struct {
	// Process context
	Pid        uint32
	Ppid       uint32
	Timestamp  uint64
	Comm       string
	ParentComm string

	// Connection info
	SourceIP   net.IP
	DestIP     net.IP
	SourcePort uint16
	DestPort   uint16

	// TLS fields
	TLSVersion      uint16
	HandshakeType   uint8
	HandshakeLength uint32
	SNI             string

	SupportedVersions []uint16
	CipherSuites      []uint16
	SupportedGroups   []uint16
	KeyShareGroups    []uint16

	ALPNValues []string
	JA4        string
	JA4Hash    string
}

// EventHeader is used for event type routing
type EventHeader struct {
	EventType uint32
}
