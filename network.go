package main

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/jnesss/bpfview/outputformats" // for GenerateConnID utility function
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

	var processInfo *types.ProcessInfo
	if info, exists := GetProcessFromCache(event.Pid); exists {
		processInfo = info
	} else {
		processInfo = &types.ProcessInfo{}
	}

	if globalLogger != nil {
		globalLogger.LogNetwork(event, processInfo)
	}

	if globalSigmaEngine != nil {

		networkUID := outputformats.GenerateConnID(event.Pid, event.Ppid,
			uint32ToNetIP(event.SrcIP),
			uint32ToNetIP(event.DstIP),
			event.SrcPort, event.DstPort)

		// Map fields for Sigma detection
		sigmaEvent := map[string]interface{}{
			// Process fields - minimal for matching since matches will get enriched in sigma.go
			"ProcessId":   event.Pid,
			"ProcessName": string(bytes.TrimRight(event.Comm[:], "\x00")),

			// every network field that will be included in any networked-based yara rule
			"SourceIp":        ipToString(event.SrcIP),
			"SourcePort":      event.SrcPort,
			"DestinationIp":   ipToString(event.DstIP),
			"DestinationPort": event.DstPort,
			"Protocol":        protocolToString(event.Protocol),
			"Initiated":       event.Direction == types.FLOW_EGRESS,

			// Correlation ID
			"network_uid": networkUID,
		}

		if event.Direction == types.FLOW_EGRESS {
			sigmaEvent["Direction"] = "egress"
		} else if event.Direction == types.FLOW_INGRESS {
			sigmaEvent["Direction"] = "ingress"
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
