package binaryanalyzer

import "time"

// BinaryAnalyzer provides binary analysis and metadata tracking
type BinaryAnalyzer interface {
	// Submit a binary path for analysis
	SubmitBinary(path string)

	// Submit a binary with pre-calculated MD5 hash
	SubmitBinaryWithHash(path string, md5Hash string)

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

	// ELF-specific information
	IsELF             bool     // Whether this is an ELF binary
	ELFType           string   // Executable, shared object, etc.
	Architecture      string   // x86_64, ARM, etc.
	Interpreter       string   // Dynamic linker path
	ImportedLibraries []string // Shared libraries imported

	// Symbol information
	ImportedSymbols     []string // Imported symbols (we don't store these now, but might in Phase 5)
	ExportedSymbols     []string // Exported symbols (we don't store these now, but might in Phase 5)
	ImportedSymbolCount int      // Count of imported symbols
	ExportedSymbolCount int      // Count of exported symbols

	IsStaticallyLinked bool     // Whether the binary is statically linked
	Sections           []string // Section names
	HasDebugInfo       bool     // Whether the binary contains debug info

	// For future vector embeddings and similarity search
	// TODO: Add vector embedding field for binary similarity search
	// VectorEmbedding []float32 // Feature vector for similarity search
	// SimilarityScore float32    // Similarity score to most similar known binary
	// SimilarBinaryHash string   // Hash of the most similar binary
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
