package main

import (
	"bytes"
	"fmt"
	"hash/fnv"
	"net"
	"strings"

	"github.com/jnesss/bpfview/types"
)

func handleDNSEvent(event *types.BPFDNSRawEvent) error {
	// Clean up process names
	comm := string(bytes.TrimRight(event.Comm[:], "\x00"))
	parentComm := string(bytes.TrimRight(event.ParentComm[:], "\x00"))

	// Create userspace event
	userEvent := types.UserSpaceDNSEvent{
		Pid:        event.Pid,
		Ppid:       event.Ppid,
		Timestamp:  event.Timestamp,
		Comm:       comm,
		ParentComm: parentComm,
		SourcePort: event.SPort,
		DestPort:   event.DPort,
		IsResponse: event.IsResponse != 0,
		DNSFlags:   event.DNSFlags,
	}

	// Parse DNS data if available
	if event.DataLen > 0 {
		actualDataLen := min(int(event.DataLen), len(event.Data))
		data := event.Data[:actualDataLen]

		if len(data) >= 12 {
			userEvent.TransactionID = uint16(data[0])<<8 | uint16(data[1])

			// Parse questions
			questionCount := int(data[4])<<8 | int(data[5])
			offset := 12 // After header

			for i := 0; i < questionCount && offset < len(data); i++ {
				question, newOffset := parseDNSQuestion(data, offset)
				if newOffset > offset {
					userEvent.Questions = append(userEvent.Questions, question)
					offset = newOffset
				} else {
					break
				}
			}

			// Parse answers if it's a response
			if userEvent.IsResponse {
				answerCount := int(data[6])<<8 | int(data[7])
				for i := 0; i < answerCount && offset < len(data); i++ {
					answer, newOffset := parseDNSAnswer(data, offset)
					if newOffset > offset {
						userEvent.Answers = append(userEvent.Answers, answer)
						offset = newOffset
					} else {
						break
					}
				}
			}

			// generate conversation id
			if !userEvent.IsResponse {
				// Use transaction ID + source port for outgoing queries
				h := fnv.New32a()
				h.Write([]byte(fmt.Sprintf("%04x-%d", userEvent.TransactionID, userEvent.SourcePort)))
				userEvent.ConversationID = fmt.Sprintf("%x", h.Sum32())
			} else {
				// For responses, flip source/dest ports to match the query
				h := fnv.New32a()
				h.Write([]byte(fmt.Sprintf("%04x-%d", userEvent.TransactionID, userEvent.DestPort))) // Use dest port which was the source port in the query
				userEvent.ConversationID = fmt.Sprintf("%x", h.Sum32())
			}
		}
	}

	// Create IP addresses
	srcIP := uint32ToNetIP(event.SrcAddr)
	dstIP := uint32ToNetIP(event.DstAddr)
	userEvent.SourceIP = srcIP
	userEvent.DestIP = dstIP

	// Filter check before any logging
	if globalEngine != nil && !globalEngine.matchDNS(&userEvent) {
		return nil
	}

	// Generate connection ID (same as network connection uid)
	uid := generateConnID(event.Pid, event.Ppid, userEvent.SourceIP, userEvent.DestIP, event.SPort, event.DPort)

	// Print the event
	eventType := "QUERY"
	if userEvent.IsResponse {
		eventType = "RESPONSE"
	}

	// Build the message using strings.Builder for efficiency
	var msg strings.Builder
	fmt.Fprintf(&msg, "%s: conn_uid=%s tx_id=0x%04x pid=%d comm=%s\n",
		eventType, uid, userEvent.TransactionID, userEvent.Pid, userEvent.Comm)
	fmt.Fprintf(&msg, "      %s:%d → %s:%d\n",
		userEvent.SourceIP, userEvent.SourcePort,
		userEvent.DestIP, userEvent.DestPort)
	fmt.Fprintf(&msg, "      DNS Flags: 0x%04x, QR bit: %v",
		event.DNSFlags, (event.DNSFlags&0x8000) != 0)

	// Always show questions for both queries and responses
	for i, q := range userEvent.Questions {
		fmt.Fprintf(&msg, "\n      Q%d: %s (Type: %s)",
			i+1, q.Name, dnsTypeToString(q.Type))
	}

	// Show answers for responses
	if userEvent.IsResponse {
		for i, a := range userEvent.Answers {
			fmt.Fprintf(&msg, "\n      A%d: %s -> ", i+1, a.Name)
			switch a.Type {
			case 1, 28: // A or AAAA
				if a.IPAddress != nil {
					fmt.Fprintf(&msg, "%s (TTL: %ds)", a.IPAddress.String(), a.TTL)
				}
			case 5: // CNAME
				fmt.Fprintf(&msg, "%s (TTL: %ds)", a.CName, a.TTL)
			default:
				fmt.Fprintf(&msg, "%s record (TTL: %ds)", dnsTypeToString(a.Type), a.TTL)
			}
		}
	}

	// Log the complete message through the logger
	globalLogger.Info("dns", "%s", msg.String())

	// Handle the file logging through the formatter
	if globalLogger != nil {
		if processinfo, exists := GetProcessFromCache(event.Pid); exists {
			return globalLogger.LogDNS(&userEvent, processinfo)
		} else {
			return globalLogger.LogDNS(&userEvent, &types.ProcessInfo{})
		}
	}

	// Submit to Sigma detection if enabled
	if globalSigmaEngine != nil {
		// For DNS queries
		if !userEvent.IsResponse {
			// Get process info from cache
			var processInfo *types.ProcessInfo
			if info, exists := GetProcessFromCache(event.Pid); exists {
				processInfo = info
			} else {
				processInfo = &types.ProcessInfo{}
			}

			for _, q := range userEvent.Questions {
				// Map fields for Sigma detection
				sigmaEvent := map[string]interface{}{
					"ProcessId":    userEvent.Pid,
					"ProcessName":  userEvent.Comm,
					"DestHostname": q.Name,
					"Initiated":    true,
					"Image":        processInfo.ExePath, // from process info
					"CommandLine":  processInfo.CmdLine, // from process info
				}

				// Create detection event
				detectionEvent := DetectionEvent{
					EventType:       "network_connection",
					Data:            sigmaEvent,
					Timestamp:       BpfTimestampToTime(event.Timestamp),
					ProcessUID:      processInfo.ProcessUID,
					PID:             event.Pid,
					DetectionSource: "dns_query",
				}

				globalSigmaEngine.SubmitEvent(detectionEvent)
			}
		}
	}

	return nil
}

// DNS parsing helper functions
func parseDNSQuestion(data []byte, offset int) (types.DNSQuestion, int) {
	var question types.DNSQuestion

	name, newOffset := parseDNSName(data, offset)
	if newOffset <= offset {
		return question, offset
	}

	if newOffset+4 > len(data) {
		return question, offset
	}

	question.Name = name
	question.Type = uint16(data[newOffset])<<8 | uint16(data[newOffset+1])
	question.Class = uint16(data[newOffset+2])<<8 | uint16(data[newOffset+3])

	return question, newOffset + 4
}

func parseDNSAnswer(data []byte, offset int) (types.DNSAnswer, int) {
	var answer types.DNSAnswer

	name, newOffset := parseDNSName(data, offset)
	if newOffset <= offset {
		return answer, offset
	}

	if newOffset+10 > len(data) {
		return answer, offset
	}

	answer.Name = name
	answer.Type = uint16(data[newOffset])<<8 | uint16(data[newOffset+1])
	answer.Class = uint16(data[newOffset+2])<<8 | uint16(data[newOffset+3])
	answer.TTL = uint32(data[newOffset+4])<<24 | uint32(data[newOffset+5])<<16 |
		uint32(data[newOffset+6])<<8 | uint32(data[newOffset+7])
	answer.DataLen = uint16(data[newOffset+8])<<8 | uint16(data[newOffset+9])

	newOffset += 10

	if int(answer.DataLen) > len(data)-newOffset {
		return answer, offset
	}

	switch answer.Type {
	case 1: // A Record
		if answer.DataLen == 4 {
			answer.IPAddress = net.IPv4(
				data[newOffset],
				data[newOffset+1],
				data[newOffset+2],
				data[newOffset+3],
			)
		}
	case 5: // CNAME
		cname, _ := parseDNSName(data, newOffset)
		answer.CName = cname
	case 28: // AAAA Record
		if answer.DataLen == 16 {
			answer.IPAddress = net.IP(data[newOffset : newOffset+16])
		}
	default:
		answer.Data = make([]byte, answer.DataLen)
		copy(answer.Data, data[newOffset:newOffset+int(answer.DataLen)])
	}

	return answer, newOffset + int(answer.DataLen)
}

func parseDNSName(data []byte, offset int) (string, int) {
	var name strings.Builder
	origOffset := offset
	ptr := false

	for offset < len(data) {
		length := int(data[offset])
		if length == 0 {
			offset++
			break
		}

		// Handle compression
		if length&0xC0 == 0xC0 {
			if offset+1 >= len(data) {
				return "", origOffset
			}

			pointerOffset := ((int(length) & 0x3F) << 8) | int(data[offset+1])
			if !ptr {
				offset += 2
			}
			ptr = true

			if pointerOffset >= origOffset {
				return "", origOffset
			}

			offset = pointerOffset
			continue
		}

		offset++
		if offset+length > len(data) {
			return "", origOffset
		}

		if name.Len() > 0 {
			name.WriteByte('.')
		}

		name.Write(data[offset : offset+length])
		offset += length
	}

	if !ptr {
		return name.String(), offset
	}
	return name.String(), origOffset + 2
}

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
