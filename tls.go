package main

import (
	"bytes"
	"fmt"
	"net"
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

func handleTLSEvent(event *BPFTLSEvent) {
	// Clean up process names
	comm := string(bytes.TrimRight(event.Comm[:], "\x00"))
	parentComm := string(bytes.TrimRight(event.ParentComm[:], "\x00"))

	// Create IP addresses
	srcIP := net.IPv4(event.SAddrA, event.SAddrB, event.SAddrC, event.SAddrD)
	dstIP := net.IPv4(event.DAddrA, event.DAddrB, event.DAddrC, event.DAddrD)

	// Generate connection ID
	uid := generateConnID(event.Pid, event.Ppid, srcIP, dstIP, event.SPort, event.DPort)

	// Construct userspace event
	userEvent := UserSpaceTLSEvent{
		Pid:        event.Pid,
		Ppid:       event.Ppid,
		Timestamp:  event.Timestamp,
		Comm:       comm,
		ParentComm: parentComm,
		SourceIP:   srcIP,
		DestIP:     dstIP,
		SourcePort: event.SPort,
		DestPort:   event.DPort,
	}

	// Parse TLS data if available
	if event.DataLen > 0 {
		actualDataLen := min(int(event.DataLen), len(event.Data))

		// Extract SNI
		userEvent.SNI = extractSNI(event.Data[:actualDataLen])

		// Extract TLS version
		if actualDataLen >= 6 {
			userEvent.TLSVersion = uint16(event.Data[1])<<8 | uint16(event.Data[2])
			userEvent.HandshakeType = event.Data[5]
		}

		// Extract additional TLS information
		userEvent.SupportedVersions = extractSupportedVersions(event.Data[:actualDataLen])
		userEvent.CipherSuites = extractCipherSuites(event.Data[:actualDataLen], 10)
		userEvent.SupportedGroups = extractSupportedGroups(event.Data[:actualDataLen])
		userEvent.KeyShareGroups = extractKeyShareGroups(event.Data[:actualDataLen])
	}

	// Filter check before any logging
	if globalEngine != nil && !globalEngine.matchTLS(&userEvent) {
		return
	}

	// Print the event
	fmt.Printf("[TLS] UID: %s Process: %s (PID: %d, PPID: %d, Parent: %s)\n",
		uid, userEvent.Comm, userEvent.Pid, userEvent.Ppid, userEvent.ParentComm)
	fmt.Printf("      %s:%d → %s:%d\n",
		userEvent.SourceIP, userEvent.SourcePort,
		userEvent.DestIP, userEvent.DestPort)

	if userEvent.TLSVersion != 0 {
		fmt.Printf("      Version: %v\n", formatTlsVersion(userEvent.TLSVersion))
	}
	if userEvent.SNI != "" {
		fmt.Printf("      SNI: %s\n", userEvent.SNI)
	}

	// Print additional TLS information
	if len(userEvent.SupportedVersions) > 0 {
		fmt.Printf("      Supported Versions: ")
		for i, version := range userEvent.SupportedVersions {
			if i > 0 {
				fmt.Printf(", ")
			}
			fmt.Printf("%s", formatTlsVersion(version))
		}
		fmt.Printf("\n")
	}

	if len(userEvent.CipherSuites) > 0 {
		fmt.Printf("      Cipher Suites: ")
		for i, cipher := range userEvent.CipherSuites {
			if i > 0 {
				fmt.Printf(", ")
			}
			fmt.Printf("0x%04x", cipher)
		}
		fmt.Printf("\n")
	}

	if len(userEvent.SupportedGroups) > 0 {
		fmt.Printf("      Supported Groups: ")
		for i, group := range userEvent.SupportedGroups {
			if i > 0 {
				fmt.Printf(", ")
			}
			fmt.Printf("%s", formatSupportedGroup(group))
		}
		fmt.Printf("\n")
	}

	if len(userEvent.KeyShareGroups) > 0 {
		fmt.Printf("      Key Share Groups: ")
		for i, group := range userEvent.KeyShareGroups {
			if i > 0 {
				fmt.Printf(", ")
			}
			fmt.Printf("%s", formatSupportedGroup(group))
		}
		fmt.Printf("\n")
	}

	if globalLogger != nil {
		globalLogger.LogTLS(&userEvent)
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

