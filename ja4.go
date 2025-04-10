// ja4.go
package main

import (
	"crypto/md5"
	"fmt"
	"sort"
	"strings"
)

// Extract ALPN values from ClientHello
func extractALPN(data []byte) []string {
	alpnValues := []string{}

	if len(data) < 43 {
		return alpnValues
	}

	// Skip through headers to extensions
	offset := 9  // Skip record header (5) and handshake header (4)
	offset += 34 // Skip version (2) and random (32)

	if offset+1 > len(data) {
		return alpnValues
	}

	// Skip session ID
	sessionIDLen := int(data[offset])
	offset += 1 + sessionIDLen

	if offset+2 > len(data) {
		return alpnValues
	}

	// Skip cipher suites
	cipherSuitesLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2 + cipherSuitesLen

	if offset+1 > len(data) {
		return alpnValues
	}

	// Skip compression methods
	compressionMethodsLen := int(data[offset])
	offset += 1 + compressionMethodsLen

	if offset+2 > len(data) {
		return alpnValues
	}

	// Process extensions
	extensionsLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2

	extensionsEnd := offset + extensionsLen
	if extensionsEnd > len(data) {
		extensionsEnd = len(data)
	}

	// Search for ALPN extension (type 0x0010)
	for offset+4 <= extensionsEnd {
		extType := int(data[offset])<<8 | int(data[offset+1])
		extLen := int(data[offset+2])<<8 | int(data[offset+3])
		offset += 4

		if extType == 0x0010 && offset+2 <= extensionsEnd {
			// ALPN extension found
			protocolListLen := int(data[offset])<<8 | int(data[offset+1])
			offset += 2

			protocolsEnd := offset + protocolListLen
			if protocolsEnd > extensionsEnd {
				protocolsEnd = extensionsEnd
			}

			// Extract each protocol
			for offset < protocolsEnd {
				if offset+1 > extensionsEnd {
					break
				}

				protocolLen := int(data[offset])
				offset++

				if offset+protocolLen <= extensionsEnd {
					protocol := string(data[offset : offset+protocolLen])
					alpnValues = append(alpnValues, protocol)
					offset += protocolLen
				} else {
					break
				}
			}

			return alpnValues
		}

		offset += extLen
	}

	return alpnValues
}

// Format ALPN values according to JA4 spec
func formatALPN(alpnValues []string) string {
	if len(alpnValues) == 0 {
		return "_"
	}

	// Use the first ALPN value
	firstALPN := alpnValues[0]

	// Convert h2 to http2 per JA4 spec
	if firstALPN == "h2" {
		return "http2"
	}

	return firstALPN
}

// IsGREASE checks if a value is a GREASE value
func isGREASE(value uint16) bool {
	// GREASE values are of the form 0xaXaX where X is the same hex value
	return (value&0x0f0f) == 0x0a0a && ((value>>4)&0x0f) == (value>>12)
}

// Remove GREASE values from cipher suites
func removeGREASE(cipherSuites []uint16) []uint16 {
	result := make([]uint16, 0, len(cipherSuites))
	for _, cipher := range cipherSuites {
		if !isGREASE(cipher) {
			result = append(result, cipher)
		}
	}
	return result
}

// CalculateJA4 generates a JA4 fingerprint from a TLS ClientHello
func CalculateJA4(event *UserSpaceTLSEvent) string {
	// Only calculate for ClientHello
	if event.HandshakeType != 0x01 {
		return ""
	}

	// q: QUIC transport (0 for regular TCP)
	quic := "0"

	// t: TLS Version (just the minor version number)
	tlsVer := fmt.Sprintf("%d", event.TLSVersion&0xFF)

	// d: SNI domain component (second-level domain)
	domain := "_"
	if event.SNI != "" {
		parts := strings.Split(event.SNI, ".")
		if len(parts) >= 2 {
			domain = parts[len(parts)-2]
		}
	}

	// z: Size of ClientHello
	size := fmt.Sprintf("%d", event.HandshakeLength)

	// a: ALPN
	alpn := formatALPN(event.ALPNValues)

	// c: Cipher suites fingerprint (first non-GREASE cipher)
	cipherFingerprint := getCipherFingerprint(event.CipherSuites)

	// Construct JA4
	ja4 := fmt.Sprintf("q%st%sd%sz%sa%sc%s",
		quic, tlsVer, domain, size, alpn, cipherFingerprint)

	return ja4
}

// Calculate the JA4 hash (MD5)
func CalculateJA4Hash(ja4 string) string {
	if ja4 == "" {
		return ""
	}
	hash := md5.Sum([]byte(ja4))
	return fmt.Sprintf("%x", hash)
}

// Get the JA4 cipher fingerprint per spec
func getCipherFingerprint(cipherSuites []uint16) string {
	// Remove GREASE values
	filteredCiphers := removeGREASE(cipherSuites)

	if len(filteredCiphers) == 0 {
		return "_"
	}

	// Return hex of first non-GREASE cipher
	return fmt.Sprintf("%04x", filteredCiphers[0])
}
