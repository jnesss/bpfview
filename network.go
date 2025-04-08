package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"log"
	"net"
)

// Helper functions for network event processing
func ipToString(ip uint32) string {
	return fmt.Sprintf("%d.%d.%d.%d",
		byte(ip),
		byte(ip>>8),
		byte(ip>>16),
		byte(ip>>24))
}

func uint32ToNetIP(ip uint32) net.IP {
	return net.IPv4(
		byte(ip),
		byte(ip>>8),
		byte(ip>>16),
		byte(ip>>24),
	)
}

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

// Connection ID generation for event correlation
func generateConnID(pid uint32, ppid uint32, srcIP net.IP, dstIP net.IP, srcPort uint16, dstPort uint16) string {
	h := fnv.New64a()
	binary.Write(h, binary.LittleEndian, pid)
	binary.Write(h, binary.LittleEndian, ppid)
	h.Write(srcIP.To4())
	h.Write(dstIP.To4())
	binary.Write(h, binary.LittleEndian, srcPort)
	binary.Write(h, binary.LittleEndian, dstPort)
	return fmt.Sprintf("%016x", h.Sum64())
}

// handleNetworkEvent processes network connection events
func handleNetworkEvent(event *NetworkEvent) {
	// Filter check right at the start
	if globalEngine != nil && !globalEngine.matchNetwork(event) {
		return
	}

	// Clean up process names
	comm := string(bytes.TrimRight(event.Comm[:], "\x00"))
	parentComm := string(bytes.TrimRight(event.ParentComm[:], "\x00"))

	// Convert uint32 IPs to net.IP for generateConnID
	srcIP := uint32ToNetIP(event.SrcIP)
	dstIP := uint32ToNetIP(event.DstIP)

	// Generate connection ID
	uid := generateConnID(event.Pid, event.Ppid, srcIP, dstIP, event.SrcPort, event.DstPort)

	direction := "→"
	if event.Direction == FLOW_INGRESS {
		direction = "←"
	}

	fmt.Printf("[NETWORK] Process: %s (PID: %d) Parent: %s (PPID: %d)\n",
		comm, event.Pid, parentComm, event.Ppid)
	fmt.Printf("          %s:%d %s %s:%d %s %d bytes\n",
		ipToString(event.SrcIP), event.SrcPort,
		direction,
		ipToString(event.DstIP), event.DstPort,
		protocolToString(event.Protocol),
		event.BytesCount)
	fmt.Printf("          ConnectionID: %s\n", uid)

	if globalLogger != nil {
		globalLogger.LogNetwork(event)
	}
}

// Program loading functions
func loadNetmonProgram() netmonObjects {
	objs := netmonObjects{}
	if err := loadNetmonObjects(&objs, nil); err != nil {
		log.Fatalf("loading netmon objects: %v", err)
	}
	return objs
}

func loadDnsmonProgram() dnsmonObjects {
	objs := dnsmonObjects{}
	if err := loadDnsmonObjects(&objs, nil); err != nil {
		log.Fatalf("loading dnsmon objects: %v", err)
	}
	return objs
}

func loadTlsmonProgram() tlsmonObjects {
	objs := tlsmonObjects{}
	if err := loadTlsmonObjects(&objs, nil); err != nil {
		log.Fatalf("loading tlsmon objects: %v", err)
	}
	return objs
}

