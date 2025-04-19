package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

type MemoryDumper struct {
	outputDir string
}

func NewMemoryDumper(outputDir string) (*MemoryDumper, error) {
	// Create dumps directory if it doesn't exist
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create dumps directory: %v", err)
	}

	return &MemoryDumper{
		outputDir: outputDir,
	}, nil
}

type memoryRegion struct {
	startAddress uint64
	endAddress   uint64
	permissions  string
	offset       uint64
	dev          string
	inode        uint64
	pathname     string
}

func (md *MemoryDumper) DumpProcessMemory(pid uint32, reason string) (string, error) {
	// Generate base filename with timestamp
	timestamp := time.Now().Format("20060102-150405")
	baseFilename := fmt.Sprintf("memdump-%d-%s", pid, timestamp)

	// Create paths for both dump and metadata
	dumpPath := filepath.Join(md.outputDir, baseFilename+".bin")
	metaPath := filepath.Join(md.outputDir, baseFilename+".txt")

	// Get process info for logging
	procInfo, exists := GetProcessFromCache(pid)
	if !exists {
		return "", fmt.Errorf("process %d not found in cache", pid)
	}

	globalLogger.Info("memory_dump", "Starting memory dump of PID %d (%s) due to: %s",
		pid, procInfo.Comm, reason)

	// Write metadata file first
	metadata := fmt.Sprintf("Process: %s (PID: %d)\n", procInfo.Comm, pid)
	metadata += fmt.Sprintf("Executable: %s\n", procInfo.ExePath)
	metadata += fmt.Sprintf("Command Line: %s\n", procInfo.CmdLine)
	metadata += fmt.Sprintf("Working Directory: %s\n", procInfo.WorkingDir)
	metadata += fmt.Sprintf("Dump Reason: %s\n", reason)
	metadata += fmt.Sprintf("Timestamp: %s\n\n", time.Now().Format(time.RFC3339))

	if err := os.WriteFile(metaPath, []byte(metadata), 0644); err != nil {
		return "", fmt.Errorf("failed to write metadata: %v", err)
	}

	// Read memory regions
	regions, err := md.readMemoryMap(pid)
	if err != nil {
		return "", fmt.Errorf("failed to read memory maps: %v", err)
	}

	// Open process memory
	memPath := fmt.Sprintf("/proc/%d/mem", pid)
	memFile, err := os.Open(memPath)
	if err != nil {
		return "", fmt.Errorf("failed to open process memory: %v", err)
	}
	defer memFile.Close()

	// Create output file for binary dump
	outFile, err := os.Create(dumpPath)
	if err != nil {
		return "", fmt.Errorf("failed to create output file: %v", err)
	}
	defer outFile.Close()

	// Write memory regions
	var totalBytes int64
	for _, region := range regions {
		// Only dump readable regions
		if !strings.Contains(region.permissions, "r") {
			continue
		}

		regionInfo := fmt.Sprintf("Region: %016x-%016x %s\n",
			region.startAddress, region.endAddress, region.permissions)
		metaFile, err := os.OpenFile(metaPath, os.O_APPEND|os.O_WRONLY, 0644)
		if err != nil {
			return "", fmt.Errorf("failed to open metadata file for append: %v", err)
		}
		if _, err := metaFile.WriteString(regionInfo); err != nil {
			metaFile.Close()
			return "", fmt.Errorf("failed to append region info: %v", err)
		}
		metaFile.Close()

		// Read and write memory contents to binary file
		size := region.endAddress - region.startAddress
		if size > 0 {
			buf := make([]byte, size)
			if _, err := memFile.ReadAt(buf, int64(region.startAddress)); err != nil {
				globalLogger.Debug("memory_dump", "Failed to read region %x-%x: %v",
					region.startAddress, region.endAddress, err)
				continue
			}

			if n, err := outFile.Write(buf); err != nil {
				return "", fmt.Errorf("failed to write memory contents: %v", err)
			} else {
				totalBytes += int64(n)
			}
		}
	}

	globalLogger.Info("memory_dump", "Memory dump complete for PID %d: %s (%.2f MB)",
		pid, baseFilename, float64(totalBytes)/1024/1024)

	return dumpPath, nil
}

func (md *MemoryDumper) readMemoryMap(pid uint32) ([]memoryRegion, error) {
	var regions []memoryRegion

	// Read /proc/PID/maps
	mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
	content, err := os.ReadFile(mapsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read memory maps: %v", err)
	}

	// Parse each line
	lines := strings.Split(string(content), "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}

		// Parse map line
		// Format: address perms offset dev inode pathname
		fields := strings.Fields(line)
		if len(fields) < 5 {
			continue
		}

		// Parse address range
		addresses := strings.Split(fields[0], "-")
		if len(addresses) != 2 {
			continue
		}

		start, err := strconv.ParseUint(addresses[0], 16, 64)
		if err != nil {
			continue
		}

		end, err := strconv.ParseUint(addresses[1], 16, 64)
		if err != nil {
			continue
		}

		// Parse other fields
		offset, _ := strconv.ParseUint(fields[2], 16, 64)
		dev := fields[3]
		inode, _ := strconv.ParseUint(fields[4], 10, 64)

		// Get pathname if present
		pathname := ""
		if len(fields) > 5 {
			pathname = strings.Join(fields[5:], " ")
		}

		regions = append(regions, memoryRegion{
			startAddress: start,
			endAddress:   end,
			permissions:  fields[1],
			offset:       offset,
			dev:          dev,
			inode:        inode,
			pathname:     pathname,
		})
	}

	return regions, nil
}

func sanitizeFilename(name string) string {
	// Replace invalid characters with underscores
	re := regexp.MustCompile(`[^a-zA-Z0-9._-]`)
	return re.ReplaceAllString(name, "_")
}
