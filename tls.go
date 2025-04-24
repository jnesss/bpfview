package main

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/jnesss/bpfview/outputformats"
	"github.com/jnesss/bpfview/types"
)

// QUIC constants
const (
	QUIC_VERSION_1     = 0x00000001 // QUIC v1
	QUIC_VERSION_2     = 0x6b3343cf // QUIC v2 draft
	QUIC_VERSION_DRAFT = 0xff000000 // IETF draft versions mask

	// QUIC packet types
	QUIC_INITIAL   = 0x0
	QUIC_0RTT      = 0x1
	QUIC_HANDSHAKE = 0x2
	QUIC_RETRY     = 0x3
)

func formatTlsVersion(input uint16) string {
	tlsVersion := "Unknown"
	switch input {
	case 0x0301:
		tlsVersion = "TLS 1.0"
	case 0x0302:
		tlsVersion = "TLS 1.1"
	case 0x0303:
		tlsVersion = "TLS 1.2"
	case 0x0304:
		tlsVersion = "TLS 1.3"
	default:
		tlsVersion = fmt.Sprintf("0x%04x", input)
	}
	return tlsVersion
}

func formatQuicVersion(input uint32) string {
	switch input {
	case QUIC_VERSION_1:
		return "QUIC v1"
	case QUIC_VERSION_2:
		return "QUIC v2 (draft)"
	default:
		if (input & QUIC_VERSION_DRAFT) == QUIC_VERSION_DRAFT {
			// Draft version (0xff000000 - 0xffffffff)
			return fmt.Sprintf("QUIC draft-0x%02x", input&0x00ffffff)
		}
		return fmt.Sprintf("QUIC 0x%08x", input)
	}
}

func getQuicPacketType(firstByte byte) uint8 {
	if (firstByte & 0x80) == 0 {
		// Short header
		return 0xff // Not a long packet
	}
	// Long header, extract packet type
	return (firstByte & 0x30) >> 4
}

func handleTLSEvent(event *types.BPFTLSEvent) {
	timer := GetPhaseTimer("tls_event")
	timer.StartTiming()
	defer timer.EndTiming()

	// Wait for process info
	timer.StartPhase("process_lookup")
	var processInfo *types.ProcessInfo
	var exists bool

	// Try up to 10 times with 5ms delay (50ms total max)
	for i := 0; i < 10; i++ {
		processInfo, exists = GetProcessFromCache(event.Pid)
		if exists {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	timer.StartPhase("create_basic_info")
	if !exists {
		// Use minimal info if we still can't find process
		processInfo = &types.ProcessInfo{
			PID:  event.Pid,
			Comm: string(bytes.TrimRight(event.Comm[:], "\x00")),
			PPID: event.Ppid,
		}
	}

	// Clean up process names
	comm := string(bytes.TrimRight(event.Comm[:], "\x00"))
	parentComm := string(bytes.TrimRight(event.ParentComm[:], "\x00"))

	// Create IP address based on IP version
	var srcIP, dstIP net.IP
	if event.IPVersion == 4 {
		// For IPv4, use only the first 4 bytes
		srcIP = net.IP(event.SAddr[:4])
		dstIP = net.IP(event.DAddr[:4])
	} else {
		// For IPv6, use all 16 bytes
		srcIP = net.IP(event.SAddr[:])
		dstIP = net.IP(event.DAddr[:])
	}

	// Generate connection ID
	uid := outputformats.GenerateBidirectionalConnID(event.Pid, event.Ppid, srcIP, dstIP, event.SPort, event.DPort)

	// Construct userspace event
	userEvent := types.UserSpaceTLSEvent{
		Pid:             event.Pid,
		Ppid:            event.Ppid,
		Timestamp:       event.Timestamp,
		Comm:            comm,
		ParentComm:      parentComm,
		SourceIP:        srcIP,
		DestIP:          dstIP,
		SourcePort:      event.SPort,
		DestPort:        event.DPort,
		Protocol:        event.Protocol,
		IPVersion:       event.IPVersion,
		HandshakeLength: event.HandshakeLength,
		// Initialize as not QUIC, will set later if needed
		IsQUIC: false,
	}

	// Check if this is TCP or UDP
	if event.Protocol == 17 { // IPPROTO_UDP - QUIC
		userEvent.IsQUIC = true
		userEvent.QUICVersion = event.Version
	}

	globalLogger.Info("tls", "DataLen: %d, Protocol: %d", event.DataLen, event.Protocol)

	// Parse TLS data if available
	timer.StartPhase("parse_tls_data")
	if event.DataLen > 0 {
		actualDataLen := min(int(event.DataLen), len(event.Data))
		globalLogger.Info("tls", "Actual data length for parsing: %d", actualDataLen)

		// Debug: print first 32 bytes of data
		globalLogger.Info("tls", "First 32 bytes of data: % x", event.Data[:min(32, actualDataLen)])

		// Handle based on protocol
		if !userEvent.IsQUIC {
			// Standard TLS over TCP
			parseTCPTLS(event.Data[:actualDataLen], &userEvent)
		} else {
			// QUIC processing
			parseQUICTLS(event.Data[:actualDataLen], &userEvent)
		}
	}

	// Filter check before any logging
	timer.StartPhase("filtering")
	if globalEngine != nil && !globalEngine.matchTLS(&userEvent) {
		return
	}

	// Print the event
	timer.StartPhase("console_logging")
	var msg strings.Builder
	fmt.Fprintf(&msg, "UID: %s Process: %s (PID: %d, PPID: %d, Parent: %s)\n",
		uid, userEvent.Comm, userEvent.Pid, userEvent.Ppid, userEvent.ParentComm)
	fmt.Fprintf(&msg, "      %s:%d → %s:%d",
		userEvent.SourceIP, userEvent.SourcePort,
		userEvent.DestIP, userEvent.DestPort)

	// Add protocol information
	proto := "TCP"
	if userEvent.IsQUIC {
		proto = "QUIC"
		fmt.Fprintf(&msg, " (%s, %s)", proto, formatQuicVersion(userEvent.QUICVersion))
	} else {
		fmt.Fprintf(&msg, " (%s)", proto)
		if userEvent.TLSVersion != 0 {
			fmt.Fprintf(&msg, "\n      Version: %v", formatTlsVersion(userEvent.TLSVersion))
		}
	}

	if userEvent.SNI != "" {
		fmt.Fprintf(&msg, "\n      SNI: %s", userEvent.SNI)
	}

	if !userEvent.IsQUIC && userEvent.HandshakeLength > 0 {
		fmt.Fprintf(&msg, "\n      ClientHello len: %d", userEvent.HandshakeLength)
	}

	// Print JA4 information for ClientHello
	if userEvent.JA4 != "" {
		fmt.Fprintf(&msg, "\n      JA4: %s", userEvent.JA4)
	}
	if userEvent.JA4Hash != "" {
		fmt.Fprintf(&msg, "\n      JA4 Hash: %s", userEvent.JA4Hash)
	}

	// Print additional TLS information
	if len(userEvent.SupportedVersions) > 0 {
		fmt.Fprintf(&msg, "\n      Supported Versions: ")
		for i, version := range userEvent.SupportedVersions {
			if i > 0 {
				fmt.Fprintf(&msg, ", ")
			}
			fmt.Fprintf(&msg, "%s", formatTlsVersion(version))
		}
	}

	if len(userEvent.CipherSuites) > 0 {
		fmt.Fprintf(&msg, "\n      Cipher Suites: ")
		for i, cipher := range userEvent.CipherSuites {
			if i > 0 {
				fmt.Fprintf(&msg, ", ")
			}
			fmt.Fprintf(&msg, "0x%04x", cipher)
		}
	}

	if len(userEvent.SupportedGroups) > 0 {
		fmt.Fprintf(&msg, "\n      Supported Groups: ")
		for i, group := range userEvent.SupportedGroups {
			if i > 0 {
				fmt.Fprintf(&msg, ", ")
			}
			fmt.Fprintf(&msg, "%s", formatSupportedGroup(group))
		}
	}

	globalLogger.Info("tls", "%s", msg.String())

	timer.StartPhase("file_logging")
	if globalLogger != nil {
		globalLogger.LogTLS(&userEvent, processInfo)
	}
}

// parseTCPTLS handles standard TLS over TCP
func parseTCPTLS(data []byte, userEvent *types.UserSpaceTLSEvent) {
	// Proper TLS record parsing:
	// Record header is 5 bytes: type(1), version(2), length(2)
	// Handshake header is 4 bytes: type(1), length(3)
	// ClientHello starts after that with: version(2), random(32), ...

	// Get the handshake message version (bytes 9-10, after both headers)
	if len(data) >= 10 { // Keep original length checks in place
		userEvent.TLSVersion = uint16(data[9])<<8 | uint16(data[10])
		userEvent.HandshakeType = data[5]
		globalLogger.Info("tls", "TLS Version bytes: %02x %02x", data[9], data[10])
	} else {
		globalLogger.Info("tls", "Not enough data to parse version (need 10, got %d)", len(data))
	}

	// Now parse extensions
	if len(data) >= 11 {
		userEvent.SNI = extractSNI(data)
		if userEvent.SNI != "" {
			globalLogger.Info("tls", "Found SNI: %s", userEvent.SNI)
		}
		userEvent.SupportedVersions = extractSupportedVersions(data)
		userEvent.CipherSuites = extractCipherSuites(data, 10)
		userEvent.SupportedGroups = extractSupportedGroups(data)
		userEvent.KeyShareGroups = extractKeyShareGroups(data)
		userEvent.ALPNValues = extractALPN(data)
	}

	if userEvent.HandshakeType == 0x01 {
		userEvent.JA4 = CalculateJA4(userEvent)
		userEvent.JA4Hash = CalculateJA4Hash(userEvent.JA4)
	}
}

// parseQUICTLS handles TLS over QUIC
func parseQUICTLS(data []byte, userEvent *types.UserSpaceTLSEvent) {
	if len(data) < 5 {
		return // Not enough data
	}

	// Extract QUIC header info
	firstByte := data[0]
	packetType := getQuicPacketType(firstByte)

	// We're primarily interested in Initial packets which contain ClientHello
	if packetType != QUIC_INITIAL {
		// For all other packet types, just log the type
		globalLogger.Info("tls", "QUIC packet type: %d", packetType)
		return
	}

	globalLogger.Info("tls", "QUIC Initial packet detected")

	// Extract CRYPTO frame containing TLS data
	// This is a simplified approach - real QUIC parsing is much more complex
	cryptoData := findQUICCryptoFrame(data)
	if cryptoData == nil {
		globalLogger.Info("tls", "No CRYPTO frame found in QUIC Initial packet")
		return
	}

	// Look for ClientHello in the CRYPTO frame (it starts with type 0x01)
	if len(cryptoData) > 0 && cryptoData[0] == 0x01 {
		// This appears to be a ClientHello
		globalLogger.Info("tls", "Found potential ClientHello in QUIC packet")

		// Extract SNI
		userEvent.SNI = extractSNIFromQUICClientHello(cryptoData)
		if userEvent.SNI != "" {
			globalLogger.Info("tls", "Found SNI in QUIC: %s", userEvent.SNI)
		}

		// Create a simplified JA4 fingerprint for QUIC
		if userEvent.SNI != "" {
			// Format: q<packetType>_<sni>_<quicVersion>
			userEvent.JA4 = fmt.Sprintf("q%d_%s_%08x",
				packetType,
				strings.ReplaceAll(userEvent.SNI, ".", "d"),
				userEvent.QUICVersion)
			userEvent.JA4Hash = CalculateJA4Hash(userEvent.JA4)
		}
	}
}

// findQUICCryptoFrame tries to locate a CRYPTO frame in a QUIC packet
// CRYPTO frame type is 0x06
func findQUICCryptoFrame(data []byte) []byte {
	// This is a simplified approach - real QUIC parsing is more complex
	// We're looking for frame type 0x06 (CRYPTO)

	// Skip the QUIC header
	// Long header format: 1 byte type + 4 bytes version + ?
	// This is incomplete - full parsing would handle connection IDs, etc.
	offset := 5 // Skip type byte and version

	// Skip source connection ID
	if offset >= len(data) {
		return nil
	}
	srcConnIDLen := int(data[offset])
	offset += 1 + srcConnIDLen

	// Skip destination connection ID
	if offset >= len(data) {
		return nil
	}
	dstConnIDLen := int(data[offset])
	offset += 1 + dstConnIDLen

	// Skip token length (variable length integer)
	// This is simplified - proper parsing would handle variable length integers
	if offset >= len(data) {
		return nil
	}
	tokenLen := int(data[offset])
	offset += 1 + tokenLen

	// Skip length field
	// Again, simplified
	if offset+2 > len(data) {
		return nil
	}
	offset += 2

	// Now look for CRYPTO frame
	for offset < len(data) {
		if offset+1 > len(data) {
			break
		}

		frameType := data[offset]
		offset++

		if frameType == 0x06 { // CRYPTO frame
			// Extract offset (variable length integer)
			// Simplified - assume 1 byte
			if offset >= len(data) {
				return nil
			}

			// Skip offset field
			offset++

			// Extract length (variable length integer)
			// Simplified - assume 1 byte
			if offset >= len(data) {
				return nil
			}

			cryptoLen := int(data[offset])
			offset++

			// Extract CRYPTO data
			if offset+cryptoLen > len(data) {
				return nil // Not enough data
			}

			return data[offset : offset+cryptoLen]
		}

		// Skip this frame (simplified)
		offset += 4 // Just a guess to advance
	}

	return nil
}

// extractSNIFromQUICClientHello extracts SNI from a TLS ClientHello in QUIC
func extractSNIFromQUICClientHello(data []byte) string {
	// The ClientHello structure in QUIC is the same as in TLS
	// But it doesn't have the TLS record layer header

	if len(data) < 40 { // Minimum size for ClientHello
		return ""
	}

	// Skip handshake type (1 byte) and length (3 bytes)
	offset := 4

	// Skip client version (2 bytes) and random (32 bytes)
	offset += 34

	if offset+1 > len(data) {
		return ""
	}

	// Skip session ID
	sessionIDLen := int(data[offset])
	offset += 1 + sessionIDLen

	if offset+2 > len(data) {
		return ""
	}

	// Skip cipher suites
	cipherSuitesLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2 + cipherSuitesLen

	if offset+1 > len(data) {
		return ""
	}

	// Skip compression methods
	compressionMethodsLen := int(data[offset])
	offset += 1 + compressionMethodsLen

	if offset+2 > len(data) {
		return ""
	}

	// Process extensions
	extensionsLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2

	extensionsEnd := offset + extensionsLen
	if extensionsEnd > len(data) {
		extensionsEnd = len(data)
	}

	for offset+4 <= extensionsEnd {
		extType := int(data[offset])<<8 | int(data[offset+1])
		extLen := int(data[offset+2])<<8 | int(data[offset+3])
		offset += 4

		if extType == 0 { // Server Name extension
			if offset+2 > extensionsEnd {
				break
			}
			offset += 2 // Skip server name list length

			if offset+1 > extensionsEnd {
				break
			}
			nameType := data[offset]
			offset++

			if nameType == 0 {
				if offset+2 > extensionsEnd {
					break
				}
				hostnameLen := int(data[offset])<<8 | int(data[offset+1])
				offset += 2

				if offset+hostnameLen <= extensionsEnd {
					return string(data[offset : offset+hostnameLen])
				}
			}
		}
		offset += extLen
	}

	return ""
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

// Extract supported versions from the supported_versions extension
func extractSupportedVersions(data []byte) []uint16 {
	versions := []uint16{}

	if len(data) < 43 { // Minimum size for TLS Client Hello
		return versions
	}

	// Skip TLS record header (5 bytes) and handshake header (4 bytes)
	offset := 9

	// Skip client version (2 bytes) and random (32 bytes)
	offset += 34

	if offset+1 > len(data) {
		return versions
	}

	// Skip session ID
	sessionIDLen := int(data[offset])
	offset += 1 + sessionIDLen

	if offset+2 > len(data) {
		return versions
	}

	// Skip cipher suites
	cipherSuitesLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2 + cipherSuitesLen

	if offset+1 > len(data) {
		return versions
	}

	// Skip compression methods
	compressionMethodsLen := int(data[offset])
	offset += 1 + compressionMethodsLen

	if offset+2 > len(data) {
		return versions
	}

	// Process extensions
	extensionsLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2

	extensionsEnd := offset + extensionsLen
	if extensionsEnd > len(data) {
		extensionsEnd = len(data)
	}

	// Search for supported_versions extension (type 0x002b)
	for offset+4 <= extensionsEnd {
		extType := int(data[offset])<<8 | int(data[offset+1])
		extLen := int(data[offset+2])<<8 | int(data[offset+3])
		offset += 4

		if extType == 0x002b && offset+1 <= extensionsEnd {
			versionsLen := int(data[offset])
			offset++

			// Extract versions
			versionsEnd := offset + versionsLen
			if versionsEnd > extensionsEnd {
				versionsEnd = extensionsEnd
			}

			for offset+2 <= versionsEnd {
				version := uint16(data[offset])<<8 | uint16(data[offset+1])
				versions = append(versions, version)
				offset += 2
			}
			return versions
		}
		offset += extLen
	}
	return versions
}

// Extract SNI from Client Hello
func extractSNI(data []byte) string {
	if len(data) < 43 { // Minimum size for TLS Client Hello
		return ""
	}

	// Skip TLS record header (5 bytes) and handshake header (4 bytes)
	offset := 9

	// Skip client version (2 bytes) and random (32 bytes)
	offset += 34

	if offset+1 > len(data) {
		return ""
	}

	// Skip session ID
	sessionIDLen := int(data[offset])
	offset += 1 + sessionIDLen

	if offset+2 > len(data) {
		return ""
	}

	// Skip cipher suites
	cipherSuitesLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2 + cipherSuitesLen

	if offset+1 > len(data) {
		return ""
	}

	// Skip compression methods
	compressionMethodsLen := int(data[offset])
	offset += 1 + compressionMethodsLen

	if offset+2 > len(data) {
		return ""
	}

	// Process extensions
	extensionsLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2

	extensionsEnd := offset + extensionsLen
	if extensionsEnd > len(data) {
		extensionsEnd = len(data)
	}

	for offset+4 <= extensionsEnd {
		extType := int(data[offset])<<8 | int(data[offset+1])
		extLen := int(data[offset+2])<<8 | int(data[offset+3])
		offset += 4

		if extType == 0 { // Server Name extension
			if offset+2 > extensionsEnd {
				break
			}
			offset += 2 // Skip server name list length

			if offset+1 > extensionsEnd {
				break
			}
			nameType := data[offset]
			offset++

			if nameType == 0 {
				if offset+2 > extensionsEnd {
					break
				}
				hostnameLen := int(data[offset])<<8 | int(data[offset+1])
				offset += 2

				if offset+hostnameLen <= extensionsEnd {
					return string(data[offset : offset+hostnameLen])
				}
			}
		}
		offset += extLen
	}
	return ""
}

// Extract cipher suites from the ClientHello
func extractCipherSuites(data []byte, maxCiphers int) []uint16 {
	ciphers := []uint16{}

	if len(data) < 43 {
		return ciphers
	}

	offset := 9  // Skip headers
	offset += 34 // Skip version and random

	if offset+1 > len(data) {
		return ciphers
	}

	// Skip session ID
	sessionIDLen := int(data[offset])
	offset += 1 + sessionIDLen

	if offset+2 > len(data) {
		return ciphers
	}

	// Read cipher suites
	cipherSuitesLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2

	cipherEnd := offset + cipherSuitesLen
	if cipherEnd > len(data) {
		cipherEnd = len(data)
	}

	count := 0
	for offset+2 <= cipherEnd && count < maxCiphers {
		cipher := uint16(data[offset])<<8 | uint16(data[offset+1])
		ciphers = append(ciphers, cipher)
		offset += 2
		count++
	}

	return ciphers
}

// Extract supported groups from the supported_groups extension
func extractSupportedGroups(data []byte) []uint16 {
	groups := []uint16{}

	if len(data) < 43 {
		return groups
	}

	offset := 9  // Skip headers
	offset += 34 // Skip version and random

	if offset+1 > len(data) {
		return groups
	}

	// Skip session ID
	sessionIDLen := int(data[offset])
	offset += 1 + sessionIDLen

	if offset+2 > len(data) {
		return groups
	}

	// Skip cipher suites
	cipherSuitesLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2 + cipherSuitesLen

	if offset+1 > len(data) {
		return groups
	}

	// Skip compression methods
	compressionMethodsLen := int(data[offset])
	offset += 1 + compressionMethodsLen

	if offset+2 > len(data) {
		return groups
	}

	// Process extensions
	extensionsLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2

	extensionsEnd := offset + extensionsLen
	if extensionsEnd > len(data) {
		extensionsEnd = len(data)
	}

	// Search for supported_groups extension (type 0x000a)
	for offset+4 <= extensionsEnd {
		extType := int(data[offset])<<8 | int(data[offset+1])
		extLen := int(data[offset+2])<<8 | int(data[offset+3])
		offset += 4

		if extType == 0x000a && offset+2 <= extensionsEnd {
			groupsLen := int(data[offset])<<8 | int(data[offset+1])
			offset += 2

			groupsEnd := offset + groupsLen
			if groupsEnd > extensionsEnd {
				groupsEnd = extensionsEnd
			}

			for offset+2 <= groupsEnd {
				group := uint16(data[offset])<<8 | uint16(data[offset+1])
				groups = append(groups, group)
				offset += 2
			}
			return groups
		}
		offset += extLen
	}
	return groups
}

// Extract key share groups from the key_share extension
func extractKeyShareGroups(data []byte) []uint16 {
	groups := []uint16{}

	if len(data) < 43 {
		return groups
	}

	offset := 9  // Skip headers
	offset += 34 // Skip version and random

	if offset+1 > len(data) {
		return groups
	}

	// Skip session ID
	sessionIDLen := int(data[offset])
	offset += 1 + sessionIDLen

	if offset+2 > len(data) {
		return groups
	}

	// Skip cipher suites
	cipherSuitesLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2 + cipherSuitesLen

	if offset+1 > len(data) {
		return groups
	}

	// Skip compression methods
	compressionMethodsLen := int(data[offset])
	offset += 1 + compressionMethodsLen

	if offset+2 > len(data) {
		return groups
	}

	// Process extensions
	extensionsLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2

	extensionsEnd := offset + extensionsLen
	if extensionsEnd > len(data) {
		extensionsEnd = len(data)
	}

	// Search for key_share extension (type 0x0033)
	for offset+4 <= extensionsEnd {
		extType := int(data[offset])<<8 | int(data[offset+1])
		extLen := int(data[offset+2])<<8 | int(data[offset+3])
		offset += 4

		if extType == 0x0033 && offset+2 <= extensionsEnd {
			clientSharesLen := int(data[offset])<<8 | int(data[offset+1])
			offset += 2

			sharesEnd := offset + clientSharesLen
			if sharesEnd > extensionsEnd {
				sharesEnd = extensionsEnd
			}

			for offset+4 <= sharesEnd {
				group := uint16(data[offset])<<8 | uint16(data[offset+1])
				groups = append(groups, group)

				// Skip this key share entry
				keyExchangeLen := int(data[offset+2])<<8 | int(data[offset+3])
				offset += 4 + keyExchangeLen
			}
			return groups
		}
		offset += extLen
	}
	return groups
}
