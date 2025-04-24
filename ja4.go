// ja4.go
package main

import (
	"crypto/sha256"
	"fmt"
	"strings"
	"strconv"
	"sort"

	"github.com/jnesss/bpfview/types"
)

// Extract ALPN values from the alpn extension
func extractALPN(data []byte) []string {
	alpnValues := []string{}

	if len(data) < 43 {
		return alpnValues
	}

	offset := 9  // Skip headers
	offset += 34 // Skip version and random

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
			alpnListLen := int(data[offset])<<8 | int(data[offset+1])
			offset += 2

			alpnEnd := offset + alpnListLen
			if alpnEnd > extensionsEnd {
				alpnEnd = extensionsEnd
			}

			for offset+1 <= alpnEnd {
				strLen := int(data[offset])
				offset++

				if offset+strLen <= alpnEnd {
					alpnValues = append(alpnValues, string(data[offset:offset+strLen]))
					offset += strLen
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
		return "00"
	} else if len(alpnValues[0]) == 2 {
		return alpnValues[0]
	} else {
		//need to check for non printable characters 0x30-0x39, 0x41-0x5A and 0x61-0x7A
		//if so print first and last characters of hex representation instead, to be done
		alpn := alpnValues[0]
		first := alpn[0]
		last := alpn[len(alpn)-1]
		return string(first) + string(last)
	}
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


// Calculate TLS Version
func CalculateTLSVersion(input uint16) string {
        tlsVersion := ""
        switch input {
        case 256:  //SSL 1.0 0x0100
                tlsVersion = "s1"
        case 512:  //SSL 2.0 0x0200
                tlsVersion = "s2"
        case 768:  //SSL 3.0 0x0300
                tlsVersion = "s3"
        case 769:  //TLS 1.0 0x0301
                tlsVersion = "10"
        case 770:  //TLS 1.1 0x0302
                tlsVersion = "11"
        case 771:  //TLS 1.2 0x0303
                tlsVersion = "12"
        case 772:  //TLS 1.3 0x0304
                tlsVersion = "13"
        case 65279:  //DLTS 1.0 0xfeff
                tlsVersion = "d1"
        case 65277:  //DLTS 1.2 0xfefd
                tlsVersion = "d2"
        case 65276:  //DLTS 1.3 0xfefc
                tlsVersion = "d3"
        default:
                tlsVersion = "00"
        }
        return tlsVersion
}

func findLargest(numbers []uint16) uint16 {
	if len(numbers) == 0 {
		return 0 // Handle empty list case
	}
	largest := numbers[0]
	for _, number := range numbers {
		if number > largest {
			largest = number
		}
	}
	return largest
}

// CalculateJA4 generates a JA4 fingerprint from a TLS ClientHello
func CalculateJA4(event *types.UserSpaceTLSEvent) string {
	// Only calculate for ClientHello
	if event.HandshakeType != 0x01 {
		return ""
	}

	// q: QUIC transport
        // t: TCP transport
	protocol := ""
	if event.Protocol == 6 {
		protocol = "t"
	} else if event.IsQUIC {
		protocol = "q"
	}

	//TLS Version of the Hello Handshake used initially, unless there is a supported version we can use
        tlsVer := CalculateTLSVersion(event.TLSVersion)
	if len(event.SupportedVersions) > 0 {
		tlsVer = CalculateTLSVersion(findLargest(event.SupportedVersions))
	}

	// d: SNI domain component, we return either 'i' if there is no SNI, or 'd' if there is a second-level domain
        sni := "i"
	if event.SNI != "" {
		// as we don't really care what this value is, besides that there is one
		// we may be able to just short circuit this?
		parts := strings.Split(event.SNI, ".")
		if len(parts) >= 2 {
			// domain = parts[len(parts)-2]
			sni = "d"
		}
	}

	// a: ALPN
	alpn := formatALPN(event.ALPNValues)


	// c: Cipher suites
	cipherHash := getCipherHash(event.CipherSuites)
	cipherCount := getCipherCount(event.CipherSuites)

	// Number of Extensions
	// need something like event.Extensions to parse and count.
	extCount := "00"

	// Construct JA4
	ja4_a := fmt.Sprintf("%s%s%s%s%s%s",
		protocol, tlsVer, sni, cipherCount, extCount, alpn)

	ja4_b := cipherHash

	//truncated SHA256 hash of the extensions, sorted
	// need something like event.Extensions to calculate

	ja4_c := ""

	ja4 := fmt.Sprintf("%s_%s_%s", ja4_a, ja4_b, ja4_c)

	return ja4
}

// Calculate the JA4_ b and c hashes (SHA256)
func CalculateSHA256Hash(value string) string {
	if value == "" {
		return ""
	}
	hash := sha256.Sum256([]byte(value))
	return fmt.Sprintf("%x", hash)
}

// Get the JA4 cipher count
func getCipherCount(cipherSuites []uint16) string {
        // Remove GREASE values
        filteredCiphers := removeGREASE(cipherSuites)

        if len(filteredCiphers) == 0 {
                return fmt.Sprintf("%02x", 0)
        }
        return strconv.Itoa(len(filteredCiphers))
}


// Get the JA4 cipher Hash
func getCipherHash(cipherSuites []uint16) string {
	// Remove GREASE values
	filteredCiphers := removeGREASE(cipherSuites)

	if len(filteredCiphers) == 0 {
		return "000000000000"
	}

	//sort unint16 list
	sort.Slice(filteredCiphers, func(i,j int) bool {
		return filteredCiphers[i] < filteredCiphers[j]
	})

	//convert each value to hex
	hexFilteredCiphers := ""

        for _, number := range filteredCiphers {
		hexFilteredCiphers = hexFilteredCiphers + fmt.Sprintf("%04x", number) + ","
	}
	hexFilteredCiphers = hexFilteredCiphers[:len(hexFilteredCiphers)-1]
	hash := CalculateSHA256Hash(hexFilteredCiphers)

	// Return just the first 12 characters
	return hash[:12]
}
