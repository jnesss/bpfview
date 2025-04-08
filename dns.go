package main

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"net"
	"strings"
)

func generateDNSConnID(event *BPFDNSRawEvent) string {
	// For DNS responses, swap source/dest to match original query
	srcIP := make(net.IP, 4)
	dstIP := make(net.IP, 4)
	binary.BigEndian.PutUint32(srcIP, event.SrcAddr)
	binary.BigEndian.PutUint32(dstIP, event.DstAddr)
	srcPort := event.SPort
	dstPort := event.DPort

	if event.IsResponse != 0 {
		// Swap src/dst to match query
		srcIP, dstIP = dstIP, srcIP
		srcPort, dstPort = dstPort, srcPort
	}

	// Get transaction ID from DNS header
	txid := binary.BigEndian.Uint16(event.Data[:2])

	h := fnv.New64a()
	binary.Write(h, binary.BigEndian, srcIP.To4())
	binary.Write(h, binary.BigEndian, dstIP.To4())
	binary.Write(h, binary.BigEndian, srcPort)
	binary.Write(h, binary.BigEndian, dstPort)
	binary.Write(h, binary.BigEndian, txid)

	return hex.EncodeToString(h.Sum(nil))
}

func handleDNSEvent(event *BPFDNSRawEvent) error {
	// Clean up process names
	comm := string(bytes.TrimRight(event.Comm[:], "\x00"))
	parentComm := string(bytes.TrimRight(event.ParentComm[:], "\x00"))

	// Create userspace event
	userEvent := UserSpaceDNSEvent{
		Pid:        event.Pid,
		Ppid:       event.Ppid,
		Timestamp:  event.Timestamp,
		Comm:       comm,
		ParentComm: parentComm,
		SourcePort: event.SPort,
		DestPort:   event.DPort,
		IsResponse: event.IsResponse != 0,
	}

	// Create IP addresses
	srcIP := make(net.IP, 4)
	dstIP := make(net.IP, 4)
	binary.BigEndian.PutUint32(srcIP, event.SrcAddr)
	binary.BigEndian.PutUint32(dstIP, event.DstAddr)
	userEvent.SourceIP = srcIP
	userEvent.DestIP = dstIP

	// Generate connection ID
	uid := generateDNSConnID(event)

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
		}
	}

	// Filter check before any logging
	if globalEngine != nil && !globalEngine.matchDNS(&userEvent) {
		return nil
	}

	// Print the event
	eventType := "QUERY"
	if userEvent.IsResponse {
		eventType = "RESPONSE"
	}

	fmt.Printf("[DNS] %s: uid=%s pid=%d comm=%s\n",
		eventType, uid, userEvent.Pid, userEvent.Comm)
	fmt.Printf("      %s:%d → %s:%d\n",
		userEvent.SourceIP, userEvent.SourcePort,
		userEvent.DestIP, userEvent.DestPort)
	fmt.Printf("      DNS Flags: 0x%04x, QR bit: %v\n",
		event.DNSFlags, (event.DNSFlags&0x8000) != 0)

	// Print questions
	for i, q := range userEvent.Questions {
		fmt.Printf("      Q%d: %s (Type: %s)\n",
			i+1, q.Name, dnsTypeToString(q.Type))
	}

	// Print answers for responses
	if userEvent.IsResponse {
		for i, a := range userEvent.Answers {
			fmt.Printf("      A%d: %s -> ", i+1, a.Name)
			switch a.Type {
			case 1: // A Record
				if a.IPAddress != nil {
					fmt.Printf("%s (TTL: %ds)\n", a.IPAddress.String(), a.TTL)
				}
			case 5: // CNAME
				fmt.Printf("%s (TTL: %ds)\n", a.CName, a.TTL)
			case 28: // AAAA
				if a.IPAddress != nil {
					fmt.Printf("%s (TTL: %ds)\n", a.IPAddress.String(), a.TTL)
				}
			default:
				fmt.Printf("%s record (TTL: %ds)\n", dnsTypeToString(a.Type), a.TTL)
			}
		}
	}

	if globalLogger != nil {
		globalLogger.LogDNS(&userEvent)
	}

	return nil
}

// DNS parsing helper functions
func parseDNSQuestion(data []byte, offset int) (DNSQuestion, int) {
	var question DNSQuestion

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

func parseDNSAnswer(data []byte, offset int) (DNSAnswer, int) {
	var answer DNSAnswer

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

