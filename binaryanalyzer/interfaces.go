package binaryanalyzer

import "time"

// BinaryAnalyzer provides binary analysis and metadata tracking
type BinaryAnalyzer interface {
	// Submit a binary path for analysis
	SubmitBinary(path string)

	// Get metadata for a binary by hash
	GetMetadataByHash(hash string) (BinaryMetadata, bool)

	// Get metadata for a binary by path
	GetMetadataByPath(path string) (BinaryMetadata, bool)

	// Close and clean up resources
	Close() error
}

// BinaryMetadata contains analysis results for a binary
type BinaryMetadata struct {
	Path       string    // Full path to binary
	MD5Hash    string    // MD5 hash
	SHA256Hash string    // SHA256 hash
	FileSize   int64     // Size in bytes
	ModTime    time.Time // Last modification time
	FirstSeen  time.Time // When this binary was first observed
}

// Config for the binary analyzer
type Config struct {
	// Database configuration
	DBPath string

	// Worker pool configuration
	Workers int

	// Logging
	Logger Logger
}

// Logger interface for outputting messages
type Logger interface {
	Debug(component, format string, args ...interface{})
	Info(component, format string, args ...interface{})
	Warning(component, format string, args ...interface{})
	Error(component, format string, args ...interface{})
}
