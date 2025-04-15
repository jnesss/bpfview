// utils.go
package outputformats

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"net"
	"time"

	"github.com/jnesss/bpfview/types"
)

// Add a way to set boot time
var bootTime time.Time

func SetBootTime(t time.Time) {
	bootTime = t
}

// Convert event type to string
func eventTypeString(eventType uint32) string {
	switch eventType {
	case types.EVENT_PROCESS_EXEC:
		return "process_exec"
	case types.EVENT_PROCESS_EXIT:
		return "process_exit"
	case types.EVENT_NET_CONNECT:
		return "net_connect"
	case types.EVENT_NET_ACCEPT:
		return "net_accept"
	case types.EVENT_NET_BIND:
		return "net_bind"
	case types.EVENT_DNS:
		return "dns"
	case types.EVENT_TLS:
		return "tls"
	default:
		return fmt.Sprintf("unknown_%d", eventType)
	}
}

// Network utility functions
func uint32ToNetIP(ip uint32) net.IP {
	return net.IPv4(
		byte(ip),
		byte(ip>>8),
		byte(ip>>16),
		byte(ip>>24),
	)
}

func ipToString(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip),
		byte(ip>>8),
		byte(ip>>16),
		byte(ip>>24))
}

// Generate connection ID for event correlation
func GenerateBidirectionalConnID(pid uint32, ppid uint32, ip1 net.IP, ip2 net.IP, port1 uint16, port2 uint16) string {
	h := fnv.New64a()
	binary.Write(h, binary.LittleEndian, pid)
	binary.Write(h, binary.LittleEndian, ppid)

	// Sort to ensure consistency regardless of packet direction
	if bytes.Compare(ip1.To4(), ip2.To4()) > 0 {
		ip1, ip2 = ip2, ip1
		port1, port2 = port2, port1
	}

	h.Write(ip1.To4())
	h.Write(ip2.To4())
	binary.Write(h, binary.LittleEndian, port1)
	binary.Write(h, binary.LittleEndian, port2)
	return fmt.Sprintf("%016x", h.Sum64())
}

// Protocol type conversion
func protocolToString(proto uint8) string {
	switch proto {
	case 1:
		return "ICMP"
	case 6:
		return "TCP"
	case 17:
		return "UDP"
	case 58:
		return "ICMPv6"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", proto)
	}
}

// TLS-related utilities
func formatTlsVersion(input uint16) string {
	switch input {
	case 0x0301:
		return "TLS 1.0"
	case 0x0302:
		return "TLS 1.1"
	case 0x0303:
		return "TLS 1.2"
	case 0x0304:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("0x%04x", input)
	}
}

func formatSupportedGroup(group uint16) string {
	switch group {
	case 0x0017:
		return "secp256r1"
	case 0x0018:
		return "secp384r1"
	case 0x0019:
		return "secp521r1"
	case 0x001D:
		return "x25519"
	case 0x001E:
		return "x448"
	case 0x0100:
		return "ffdhe2048"
	case 0x0101:
		return "ffdhe3072"
	case 0x0102:
		return "ffdhe4096"
	case 0x0103:
		return "ffdhe6144"
	case 0x0104:
		return "ffdhe8192"
	default:
		return fmt.Sprintf("0x%04x", group)
	}
}

// DNS-related utilities
func dnsTypeToString(recordType uint16) string {
	switch recordType {
	case 1:
		return "A"
	case 2:
		return "NS"
	case 5:
		return "CNAME"
	case 6:
		return "SOA"
	case 12:
		return "PTR"
	case 15:
		return "MX"
	case 16:
		return "TXT"
	case 28:
		return "AAAA"
	case 33:
		return "SRV"
	case 257:
		return "CAA"
	default:
		return fmt.Sprintf("TYPE%d", recordType)
	}
}

// BPF timestamp conversion
func BpfTimestampToTime(bpfTimestamp uint64) time.Time {
	return bootTime.Add(time.Duration(bpfTimestamp))
}

// Field cleaning utilities
func cleanField(value string, defaultValue string) string {
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
