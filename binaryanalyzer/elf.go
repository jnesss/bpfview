package binaryanalyzer

import (
	"debug/elf"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
)

// ELFInfo holds detailed information about an ELF binary
type ELFInfo struct {
	Type               string
	Architecture       string
	Interpreter        string
	ImportedLibraries  []string
	ImportedSymbols    []string
	ExportedSymbols    []string
	IsStaticallyLinked bool
	Sections           []string
	HasDebugInfo       bool
}

// AnalyzeELF performs detailed analysis on an ELF binary
func AnalyzeELF(path string) (*ELFInfo, error) {
	// Open the ELF file
	elfFile, err := elf.Open(path)
	if err != nil {
		return nil, err
	}
	defer elfFile.Close()

	info := &ELFInfo{}

	// Get ELF type
	switch elfFile.Type {
	case elf.ET_EXEC:
		info.Type = "executable"
	case elf.ET_DYN:
		info.Type = "shared object"
	case elf.ET_REL:
		info.Type = "relocatable"
	case elf.ET_CORE:
		info.Type = "core dump"
	default:
		info.Type = fmt.Sprintf("unknown (%d)", elfFile.Type)
	}

	// Get architecture
	info.Architecture = elfFile.Machine.String()

	// Get interpreter (dynamic linker path)
	if interp := elfFile.Section(".interp"); interp != nil {
		if data, err := interp.Data(); err == nil {
			// Remove null terminator
			info.Interpreter = strings.TrimRight(string(data), "\x00")
		}
	}

	// Get imported libraries from dynamic section
	libraries, err := getImportedLibraries(elfFile)
	if err == nil {
		info.ImportedLibraries = libraries
	}

	// Get imported symbols
	imports, err := getImportedSymbols(elfFile)
	if err == nil {
		info.ImportedSymbols = imports
	}

	// Get exported symbols
	exports, err := getExportedSymbols(elfFile)
	if err == nil {
		info.ExportedSymbols = exports
	}

	// Check if statically linked
	info.IsStaticallyLinked = (len(info.ImportedLibraries) == 0 && len(info.ImportedSymbols) > 0)

	// Get section names
	for _, section := range elfFile.Sections {
		info.Sections = append(info.Sections, section.Name)
	}

	// Check for debug info
	for _, name := range info.Sections {
		if strings.HasPrefix(name, ".debug") {
			info.HasDebugInfo = true
			break
		}
	}

	return info, nil
}

// getImportedLibraries extracts shared library dependencies properly
func getImportedLibraries(elfFile *elf.File) ([]string, error) {
	var libraries []string

	// Get dynamic section
	dynamicSection := elfFile.Section(".dynamic")
	if dynamicSection == nil {
		return nil, errors.New("no dynamic section found")
	}

	// Get string table
	dynstrSection := elfFile.Section(".dynstr")
	if dynstrSection == nil {
		return nil, errors.New("no dynstr section found")
	}

	// Read string table data
	dynstrData, err := dynstrSection.Data()
	if err != nil {
		return nil, fmt.Errorf("error reading dynstr section: %w", err)
	}

	// Read dynamic section data
	dynamicData, err := dynamicSection.Data()
	if err != nil {
		return nil, fmt.Errorf("error reading dynamic section: %w", err)
	}

	// Determine entry size and format based on architecture
	var entrySize int
	var is64bit bool

	// Check if we're dealing with a 64-bit ELF
	is64bit = (elfFile.Class == elf.ELFCLASS64)

	if is64bit {
		entrySize = 16 // 64-bit: two 8-byte values (tag and val)
	} else {
		entrySize = 8 // 32-bit: two 4-byte values (tag and val)
	}

	// Parse dynamic entries
	for offset := 0; offset < len(dynamicData); offset += entrySize {
		if offset+entrySize > len(dynamicData) {
			break
		}

		var tag, val uint64

		// Parse tag and value based on ELF class
		if is64bit {
			tag = readUint64(dynamicData[offset:offset+8], elfFile.ByteOrder)
			val = readUint64(dynamicData[offset+8:offset+16], elfFile.ByteOrder)
		} else {
			tag = uint64(readUint32(dynamicData[offset:offset+4], elfFile.ByteOrder))
			val = uint64(readUint32(dynamicData[offset+4:offset+8], elfFile.ByteOrder))
		}

		// DT_NEEDED entries specify required libraries
		if tag == uint64(elf.DT_NEEDED) {
			// Val contains the offset into dynstr
			if int(val) < len(dynstrData) {
				// Extract null-terminated string from dynstr
				end := int(val)
				for end < len(dynstrData) && dynstrData[end] != 0 {
					end++
				}

				if end > int(val) {
					libName := string(dynstrData[val:end])
					if !contains(libraries, libName) {
						libraries = append(libraries, libName)
					}
				}
			}
		}
	}

	return libraries, nil
}

// Helper functions to read integers with the proper byte order
func readUint32(b []byte, order binary.ByteOrder) uint32 {
	return order.Uint32(b)
}

func readUint64(b []byte, order binary.ByteOrder) uint64 {
	return order.Uint64(b)
}

// getImportedSymbols extracts imported symbols
func getImportedSymbols(elfFile *elf.File) ([]string, error) {
	var imports []string

	// Get symbols from dynsym
	symbols, err := elfFile.DynamicSymbols()
	if err != nil {
		return nil, err
	}

	// Debug: Print total number of dynamic symbols
	fmt.Printf("DEBUG: Total dynamic symbols: %d\n", len(symbols))

	// Collect imported symbols (symbols with no value/addr)
	for _, sym := range symbols {
		// Skip empty names
		if sym.Name == "" {
			continue
		}

		// Check if it's an import (undefined section)
		if sym.Section == elf.SHN_UNDEF {
			imports = append(imports, sym.Name)
		}
	}

	fmt.Printf("DEBUG: Found %d imported symbols\n", len(imports))
	return imports, nil
}

// getExportedSymbols extracts exported symbols
func getExportedSymbols(elfFile *elf.File) ([]string, error) {
	var exports []string

	// Get symbols from dynsym
	symbols, err := elfFile.DynamicSymbols()
	if err != nil {
		return nil, err
	}

	// Collect exported symbols (defined global/weak symbols)
	for _, sym := range symbols {
		// Skip empty names
		if sym.Name == "" {
			continue
		}

		// Check if it's an export (defined section, not UNDEF)
		// Also check symbol type and binding - we want global or weak symbols that are objects or functions
		binding := elf.ST_BIND(sym.Info)
		symType := elf.ST_TYPE(sym.Info)

		if sym.Section != elf.SHN_UNDEF &&
			(binding == elf.STB_GLOBAL || binding == elf.STB_WEAK) &&
			(symType == elf.STT_OBJECT || symType == elf.STT_FUNC) {
			exports = append(exports, sym.Name)
		}
	}

	fmt.Printf("DEBUG: Found %d exported symbols\n", len(exports))
	return exports, nil
}

// contains checks if a string is in a slice
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if s == item {
			return true
		}
	}
	return false
}
