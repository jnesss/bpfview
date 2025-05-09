package binaryanalyzer

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// analyzerImpl implements the BinaryAnalyzer interface
type analyzerImpl struct {
	db     *sql.DB
	logger Logger
}

// Ensure implementation satisfies interface
var _ BinaryAnalyzer = (*analyzerImpl)(nil)

// New creates a new BinaryAnalyzer
func New(config Config) (BinaryAnalyzer, error) {
	// Create log directory if needed
	if err := os.MkdirAll(filepath.Dir(config.DBPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create directory: %v", err)
	}

	// Open database
	db, err := sql.Open("sqlite3", config.DBPath)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %v", err)
	}

	// Initialize schema
	if err := initBinarySchema(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to initialize schema: %v", err)
	}

	analyzer := &analyzerImpl{
		db:     db,
		logger: config.Logger,
	}

	return analyzer, nil
}

// SubmitBinary processes a binary file for analysis
func (a *analyzerImpl) SubmitBinary(path string) {
	// Basic validation
	if path == "" {
		return
	}

	// Get file info
	fileInfo, err := os.Stat(path)
	if err != nil {
		a.logger.Warning("binary", "Failed to stat file %s: %v", path, err)
		return
	}

	// Skip directories
	if fileInfo.IsDir() {
		return
	}

	// Calculate MD5 hash
	md5Hash, err := CalculateMD5(path)
	if err != nil {
		a.logger.Warning("binary", "Failed to calculate MD5 for %s: %v", path, err)
		return
	}

	// Calculate SHA256 hash
	sha256Hash, err := CalculateSHA256(path)
	if err != nil {
		a.logger.Warning("binary", "Failed to calculate SHA256 for %s: %v", path, err)
		return
	}

	// Store in database
	now := time.Now()
	_, err = a.db.Exec(`
		INSERT INTO binaries (path, md5_hash, sha256_hash, file_size, mod_time, first_seen)
		VALUES (?, ?, ?, ?, ?, ?)`, path, md5Hash, sha256Hash, fileInfo.Size(), fileInfo.ModTime(), now)

	if err != nil {
		a.logger.Warning("binary", "Failed to store binary in database: %v", err)
		return
	}

	a.logger.Info("binary", "Analyzed %s: MD5=%s, SHA256=%s", path, md5Hash, sha256Hash)
}

// GetMetadataByHash retrieves binary metadata by its MD5 hash
func (a *analyzerImpl) GetMetadataByHash(hash string) (BinaryMetadata, bool) {
	var metadata BinaryMetadata

	err := a.db.QueryRow(`
		SELECT path, md5_hash, sha256_hash, file_size, mod_time, first_seen
		FROM binaries
		WHERE md5_hash = ?
	`, hash).Scan(
		&metadata.Path,
		&metadata.MD5Hash,
		&metadata.SHA256Hash,
		&metadata.FileSize,
		&metadata.ModTime,
		&metadata.FirstSeen,
	)
	if err != nil {
		return BinaryMetadata{}, false
	}

	return metadata, true
}

// GetMetadataByPath retrieves binary metadata by its file path
func (a *analyzerImpl) GetMetadataByPath(path string) (BinaryMetadata, bool) {
	var metadata BinaryMetadata

	err := a.db.QueryRow(`
		SELECT path, md5_hash, sha256_hash, file_size, mod_time, first_seen
		FROM binaries
		WHERE path = ?
	`, path).Scan(
		&metadata.Path,
		&metadata.MD5Hash,
		&metadata.SHA256Hash,
		&metadata.FileSize,
		&metadata.ModTime,
		&metadata.FirstSeen,
	)
	if err != nil {
		a.logger.Warning("binary", "Failed to GetMetadataByPath: %v", err)
		return BinaryMetadata{}, false
	}

	return metadata, true
}

// Close closes the database connection
func (a *analyzerImpl) Close() error {
	return a.db.Close()
}
