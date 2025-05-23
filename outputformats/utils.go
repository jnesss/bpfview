// utils.go
package outputformats

import (
	"bytes"
	"crypto/sha1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"net"
	"strings"
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
	case types.EVENT_PROCESS_FORK:
		return "process_fork"
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

// FormatTCPFlags converts raw TCP flags byte to a readable string
func FormatTCPFlags(flags uint8) string {
	var result []string

	if (flags & 0x01) != 0 {
		result = append(result, "FIN")
	}
	if (flags & 0x02) != 0 {
		result = append(result, "SYN")
	}
	if (flags & 0x04) != 0 {
		result = append(result, "RST")
	}
	if (flags & 0x08) != 0 {
		result = append(result, "PSH")
	}
	if (flags & 0x10) != 0 {
		result = append(result, "ACK")
	}
	if (flags & 0x20) != 0 {
		result = append(result, "URG")
	}
	if (flags & 0x40) != 0 {
		result = append(result, "ECE")
	}
	if (flags & 0x80) != 0 {
		result = append(result, "CWR")
	}

	if len(result) == 0 {
		return "-"
	}
	return strings.Join(result, ",")
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

func GenerateCommunityID(sIP, dIP net.IP, sPort, dPort uint16, proto uint8, seed uint16) string {
	// Get the packed bytes in network byte order
	seedBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(seedBytes, seed)

	// Ensure IPs are 4 or 16 bytes
	sAddr := sIP.To4()
	if sAddr == nil {
		sAddr = sIP.To16()
	}
	dAddr := dIP.To4()
	if dAddr == nil {
		dAddr = dIP.To16()
	}

	// Order endpoints so smaller IP:port comes first
	if bytes.Compare(sAddr, dAddr) > 0 ||
		(bytes.Equal(sAddr, dAddr) && sPort > dPort) {
		// Swap endpoints
		sAddr, dAddr = dAddr, sAddr
		sPort, dPort = dPort, sPort
	}

	// Allocate buffer for hash input
	// seed(2) + saddr(4/16) + daddr(4/16) + proto(1) + pad(1) + sport(2) + dport(2)
	buf := new(bytes.Buffer)

	// Write in network byte order
	buf.Write(seedBytes)
	buf.Write(sAddr)
	buf.Write(dAddr)
	buf.WriteByte(proto)
	buf.WriteByte(0) // padding
	binary.Write(buf, binary.BigEndian, sPort)
	binary.Write(buf, binary.BigEndian, dPort)

	// Calculate SHA1
	h := sha1.New()
	h.Write(buf.Bytes())

	// Base64 encode
	b64 := base64.StdEncoding.EncodeToString(h.Sum(nil))

	// Return version 1 prefix with base64 hash
	return fmt.Sprintf("1:%s", b64)
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
