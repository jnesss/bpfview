package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/fnv"
	"log"
	"net"
	"strings"

	"github.com/jnesss/bpfview/types"
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
func handleNetworkEvent(event *types.NetworkEvent) {
	// Filter check right at the start
	if globalEngine != nil && !globalEngine.matchNetwork(event) {
		return
	}

	// Clean up process names
	comm := string(bytes.TrimRight(event.Comm[:], "\x00"))
	parentComm := string(bytes.TrimRight(event.ParentComm[:], "\x00"))
	direction := "→"
	if event.Direction == types.FLOW_INGRESS {
		direction = "←"
	}

	var msg strings.Builder
	fmt.Fprintf(&msg, "Process: %s (PID: %d) Parent: %s (PPID: %d)\n",
		comm, event.Pid, parentComm, event.Ppid)
	fmt.Fprintf(&msg, "      %s:%d %s %s:%d %s %d bytes",
		ipToString(event.SrcIP), event.SrcPort,
		direction,
		ipToString(event.DstIP), event.DstPort,
		protocolToString(event.Protocol),
		event.BytesCount)

	globalLogger.Info("network", "%s", msg.String())

	if globalLogger != nil {
		if processinfo, exists := GetProcessFromCache(event.Pid); exists {
			globalLogger.LogNetwork(event, processinfo)
		} else {
			globalLogger.LogNetwork(event, &types.ProcessInfo{})
		}
	}

	if globalSigmaEngine != nil {

		// Get process info from cache
		var processInfo *types.ProcessInfo
		if info, exists := GetProcessFromCache(event.Pid); exists {
			processInfo = info
		} else {
			processInfo = &types.ProcessInfo{}
		}

		// Map fields for Sigma detection
		sigmaEvent := map[string]interface{}{
			"ProcessId":       event.Pid,
			"ProcessName":     string(bytes.TrimRight(event.Comm[:], "\x00")),
			"Image":           processInfo.ExePath,
			"CommandLine":     processInfo.CmdLine,
			"DestinationPort": event.DstPort,
			"DestinationIp":   ipToString(event.DstIP),
			"Initiated":       event.Direction == types.FLOW_EGRESS,
		}

		// Create detection event
		detectionEvent := DetectionEvent{
			EventType:       "network_connection",
			Data:            sigmaEvent,
			Timestamp:       BpfTimestampToTime(event.Timestamp),
			ProcessUID:      processInfo.ProcessUID,
			PID:             event.Pid,
			DetectionSource: "network_connection",
		}

		globalSigmaEngine.SubmitEvent(detectionEvent)
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
