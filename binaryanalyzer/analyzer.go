package binaryanalyzer

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	_ "github.com/tursodatabase/limbo" // Import the driver
)

// Global state for the single database connection
var (
	globalDB               *sql.DB
	initialized            bool
	initMutex              sync.Mutex
	verificationInProgress sync.Map
	verificationTimeout    = 10 * time.Second
)

// initializeDB ensures we have a single global database connection
func initializeDB(dbPath string) error {
	initMutex.Lock()
	defer initMutex.Unlock()

	if initialized && globalDB != nil {
		return nil
	}

	// Create log directory if needed
	dirPath := filepath.Dir(dbPath)
	if err := os.MkdirAll(dirPath, 0755); err != nil {
		return fmt.Errorf("failed to create directory %s: %v", dirPath, err)
	}

	var err error
	globalDB, err = sql.Open("sqlite3", dbPath)
	if err != nil {
		return fmt.Errorf("failed to open database: %v", err)
	}

	// CRITICAL: Force a single connection to avoid the multi-connection issue
	globalDB.SetMaxOpenConns(1)
	globalDB.SetMaxIdleConns(1)

	// Verify connection works
	if err := globalDB.Ping(); err != nil {
		globalDB.Close()
		return fmt.Errorf("database connection failed: %v", err)
	}

	// Initialize schema
	if err := initBinarySchema(); err != nil {
		globalDB.Close()
		globalDB = nil
		return fmt.Errorf("failed to initialize schema: %v", err)
	}

	initialized = true
	return nil
}

// initBinarySchema creates the database tables for binary metadata
// (moved from schema.go to eliminate that file)
func initBinarySchema() error {
	sql := `
    CREATE TABLE IF NOT EXISTS binaries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        path TEXT NOT NULL,
        md5_hash TEXT NOT NULL UNIQUE,
        sha256_hash TEXT,
        file_size INTEGER NOT NULL,
        mod_time DATETIME NOT NULL,
        first_seen DATETIME NOT NULL,
        
        -- ELF information
        is_elf BOOLEAN DEFAULT 0,
        elf_type TEXT,
        architecture TEXT,
        interpreter TEXT,
        imported_libraries TEXT, -- JSON array
        imported_symbols_count INTEGER DEFAULT 0,
        exported_symbols_count INTEGER DEFAULT 0,
        is_statically_linked BOOLEAN DEFAULT 0,
        sections TEXT, -- JSON array
        has_debug_info BOOLEAN DEFAULT 0,
        
        -- Package information
        is_from_package BOOLEAN DEFAULT 0,
        package_name TEXT,
        package_version TEXT,
        package_verified BOOLEAN DEFAULT 0,
        package_manager TEXT,
        
        analyzed BOOLEAN DEFAULT 0
        );`

	_, err := globalDB.Exec(sql)
	if err != nil {
		return fmt.Errorf("failed to create binaries table: %v", err)
	}

	// Execute the index creation separately for better error reporting
	_, err = globalDB.Exec("CREATE INDEX IF NOT EXISTS idx_binary_md5 ON binaries(md5_hash);")
	if err != nil {
		return fmt.Errorf("failed to create md5 index: %v", err)
	}

	_, err = globalDB.Exec("CREATE INDEX IF NOT EXISTS idx_binary_path ON binaries(path);")
	if err != nil {
		return fmt.Errorf("failed to create path index: %v", err)
	}

	return nil
}

// analyzerImpl implements the BinaryAnalyzer interface
type analyzerImpl struct {
	logger            Logger
	newBinaryCallback func(BinaryMetadata)
	dbPath            string
}

// Ensure implementation satisfies interface
var _ BinaryAnalyzer = (*analyzerImpl)(nil)

// New creates a new BinaryAnalyzer
func New(config Config) (BinaryAnalyzer, error) {
	// Initialize the database connection if it hasn't been initialized yet
	if err := initializeDB(config.DBPath); err != nil {
		return nil, err
	}

	analyzer := &analyzerImpl{
		logger: config.Logger,
		dbPath: config.DBPath,
	}

	return analyzer, nil
}

// isVerificationInProgress checks if verification is already happening for a binary
func (a *analyzerImpl) isVerificationInProgress(path string) bool {
	if val, exists := verificationInProgress.Load(path); exists {
		expirationTime, ok := val.(time.Time)
		if ok && time.Now().Before(expirationTime) {
			a.logger.Debug("binary", "Verification already in progress for %s, skipping", path)
			return true
		}
		// Expired entry, clean it up
		verificationInProgress.Delete(path)
	}
	return false
}

// markVerificationInProgress sets tracking for a binary being verified
func (a *analyzerImpl) markVerificationInProgress(path string) {
	// Set expiration time for this verification
	expirationTime := time.Now().Add(verificationTimeout)
	verificationInProgress.Store(path, expirationTime)

	// Schedule cleanup after timeout to prevent stale entries
	go func() {
		time.Sleep(verificationTimeout)
		verificationInProgress.Delete(path)
	}()
}

// SubmitBinary calculates the MD5 hash and then calls SubmitBinaryWithHash
func (a *analyzerImpl) SubmitBinary(path string) {
	// Basic validation
	if path == "" {
		a.logger.Debug("binary", "Empty path submitted, skipping")
		return
	}

	// Calculate MD5 hash
	md5Hash, err := CalculateMD5(path)
	if err != nil {
		a.logger.Warning("binary", "Failed to calculate MD5 for %s: %v", path, err)
		return
	}

	// Call the implementation with the calculated hash
	a.SubmitBinaryWithHash(path, md5Hash)
}

// SubmitBinaryWithHash processes a binary file with a pre-calculated MD5 hash
func (a *analyzerImpl) SubmitBinaryWithHash(path string, md5Hash string) {
	// Skip if already being verified to prevent recursion
	if a.isVerificationInProgress(path) {
		return
	}

	// Mark as in-progress with auto-expiration
	a.markVerificationInProgress(path)
	defer verificationInProgress.Delete(path)

	// Basic validation
	if path == "" || md5Hash == "" {
		a.logger.Debug("binary", "Empty path or empty md5hash submitted, skipping")
		return
	}

	a.logger.Info("binary", "Processing binary: %s", path)

	// Get file info
	fileInfo, err := os.Stat(path)
	if err != nil {
		a.logger.Warning("binary", "Failed to stat file %s: %v", path, err)
		return
	}

	// Skip directories
	if fileInfo.IsDir() {
		a.logger.Debug("binary", "Skipping directory: %s", path)
		return
	}

	// Calculate SHA256 hash
	sha256Hash, err := CalculateSHA256(path)
	if err != nil {
		a.logger.Warning("binary", "Failed to calculate SHA256 for %s: %v", path, err)
		return
	}

	// Analyze ELF metadata if applicable
	var elfInfo *ELFInfo
	isELF := false
	if isLinuxExecutable(path) {
		if info, err := AnalyzeELF(path); err == nil {
			isELF = true
			elfInfo = info
			a.logger.Info("binary", "ELF analysis successful for %s: %s %s",
				path, info.Type, info.Architecture)
		} else {
			a.logger.Debug("binary", "Not an ELF binary or ELF analysis failed: %v", err)
		}
	}

	// Package verification
	var isFromPackage bool
	var packageName, packageVersion, packageManager string
	var packageVerified bool

	verifier := CreatePackageVerifier()
	if verifier != nil && verifier.IsAvailable() {
		packageInfo, err := verifier.Verify(path)
		if err == nil {
			isFromPackage = packageInfo.IsFromPackage
			packageName = packageInfo.PackageName
			packageVersion = packageInfo.PackageVersion
			packageVerified = packageInfo.Verified
			packageManager = packageInfo.Manager

			if isFromPackage {
				a.logger.Info("binary", "Package verification: %s belongs to %s (%s), verified: %v",
					path, packageName, packageVersion, packageVerified)
			} else {
				a.logger.Info("binary", "Binary %s is not part of any system package", path)
			}
		}
	}

	// Process ELF info for storage
	var librariesJSON, sectionsJSON string
	var importedSymbolCount, exportedSymbolCount int

	if elfInfo != nil {
		// Marshal libraries and sections to JSON
		importedLibraries, _ := json.Marshal(elfInfo.ImportedLibraries)
		sections, _ := json.Marshal(elfInfo.Sections)
		librariesJSON = string(importedLibraries)
		sectionsJSON = string(sections)

		// Extract symbol counts
		importedSymbolCount = len(elfInfo.ImportedSymbols)
		exportedSymbolCount = len(elfInfo.ExportedSymbols)
	} else {
		// Default empty arrays for non-ELF binaries
		librariesJSON = "[]"
		sectionsJSON = "[]"
	}

	// Check if record exists
	var exists bool
	err = globalDB.QueryRow("SELECT 1 FROM binaries WHERE md5_hash = ? LIMIT 1", md5Hash).Scan(&exists)
	now := time.Now()

	// Insert or update based on existence
	if err == sql.ErrNoRows || !exists {
		// Insert new record
		_, err = globalDB.Exec(`
            INSERT INTO binaries (
                path, md5_hash, sha256_hash, file_size, mod_time, first_seen,
                is_elf, elf_type, architecture, interpreter, 
                imported_libraries, imported_symbols_count, exported_symbols_count,
                is_statically_linked, sections, has_debug_info,
                is_from_package, package_name, package_version, package_verified, package_manager,
                analyzed
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)
        `,
			path, md5Hash, sha256Hash, fileInfo.Size(), fileInfo.ModTime(), now,
			isELF,
			elfInfoValue(elfInfo, "Type"),
			elfInfoValue(elfInfo, "Architecture"),
			elfInfoValue(elfInfo, "Interpreter"),
			librariesJSON,
			importedSymbolCount,
			exportedSymbolCount,
			elfInfoBool(elfInfo, "IsStaticallyLinked"),
			sectionsJSON,
			elfInfoBool(elfInfo, "HasDebugInfo"),
			isFromPackage,
			packageName,
			packageVersion,
			packageVerified,
			packageManager)

		if err != nil {
			a.logger.Error("binary", "Failed to insert binary %s: %v", path, err)
			return
		}
		a.logger.Info("binary", "Inserted new binary %s: MD5=%s", path, md5Hash)

		// Notify about new binary via callback
		if a.newBinaryCallback != nil {
			// Create metadata object
			metadata := BinaryMetadata{
				Path:                path,
				MD5Hash:             md5Hash,
				SHA256Hash:          sha256Hash,
				FileSize:            fileInfo.Size(),
				ModTime:             fileInfo.ModTime(),
				FirstSeen:           now,
				IsELF:               isELF,
				ELFType:             elfInfoValue(elfInfo, "Type").(string),
				Architecture:        elfInfoValue(elfInfo, "Architecture").(string),
				Interpreter:         elfInfoValue(elfInfo, "Interpreter").(string),
				ImportedLibraries:   getElfLibraries(elfInfo),
				ImportedSymbolCount: importedSymbolCount,
				ExportedSymbolCount: exportedSymbolCount,
				IsStaticallyLinked:  elfInfoBool(elfInfo, "IsStaticallyLinked"),
				HasDebugInfo:        elfInfoBool(elfInfo, "HasDebugInfo"),
				IsFromPackage:       isFromPackage,
				PackageName:         packageName,
				PackageVersion:      packageVersion,
				PackageVerified:     packageVerified,
				PackageManager:      packageManager,
			}

			// Call the callback
			a.newBinaryCallback(metadata)
		}
	} else {
		// Update existing record
		_, err = globalDB.Exec(`
            UPDATE binaries SET
                is_elf = CASE WHEN ? THEN ? ELSE is_elf END,
                elf_type = CASE WHEN ? THEN ? ELSE elf_type END,
                architecture = CASE WHEN ? THEN ? ELSE architecture END,
                interpreter = CASE WHEN ? THEN ? ELSE interpreter END,
                imported_libraries = CASE WHEN ? THEN ? ELSE imported_libraries END,
                imported_symbols_count = CASE WHEN ? THEN ? ELSE imported_symbols_count END,
                exported_symbols_count = CASE WHEN ? THEN ? ELSE exported_symbols_count END,
                is_statically_linked = CASE WHEN ? THEN ? ELSE is_statically_linked END,
                sections = CASE WHEN ? THEN ? ELSE sections END,
                has_debug_info = CASE WHEN ? THEN ? ELSE has_debug_info END,
                is_from_package = ?,
                package_name = ?,
                package_version = ?,
                package_verified = ?,
                package_manager = ?,
                analyzed = 1
            WHERE md5_hash = ?
        `,
			isELF, isELF,
			isELF, elfInfoValue(elfInfo, "Type"),
			isELF, elfInfoValue(elfInfo, "Architecture"),
			isELF, elfInfoValue(elfInfo, "Interpreter"),
			isELF, librariesJSON,
			isELF, importedSymbolCount,
			isELF, exportedSymbolCount,
			isELF, elfInfoBool(elfInfo, "IsStaticallyLinked"),
			isELF, sectionsJSON,
			isELF, elfInfoBool(elfInfo, "HasDebugInfo"),
			isFromPackage,
			packageName,
			packageVersion,
			packageVerified,
			packageManager,
			md5Hash)

		if err != nil {
			a.logger.Error("binary", "Failed to update binary %s: %v", path, err)
			return
		}
		a.logger.Info("binary", "Updated existing binary %s: MD5=%s", path, md5Hash)
	}
}

// GetMetadataByHash retrieves binary metadata by its MD5 hash
func (a *analyzerImpl) GetMetadataByHash(hash string) (BinaryMetadata, bool) {
	var metadata BinaryMetadata
	var importedLibrariesJSON, sectionsJSON string
	var isELF, isStaticallyLinked, hasDebugInfo sql.NullBool
	var elfType, architecture, interpreter sql.NullString
	var importSymCount, exportSymCount sql.NullInt64

	// Using global DB connection
	err := globalDB.QueryRow(`
        SELECT md5_hash, sha256_hash, file_size, mod_time, first_seen,
               is_elf, elf_type, architecture, interpreter, 
               imported_libraries, imported_symbols_count, exported_symbols_count,
               is_statically_linked, sections, has_debug_info
        FROM binaries
        WHERE md5_hash = ?
        `, hash).Scan(
		&metadata.MD5Hash,
		&metadata.SHA256Hash,
		&metadata.FileSize,
		&metadata.ModTime,
		&metadata.FirstSeen,
		&isELF,
		&elfType,
		&architecture,
		&interpreter,
		&importedLibrariesJSON,
		&importSymCount,
		&exportSymCount,
		&isStaticallyLinked,
		&sectionsJSON,
		&hasDebugInfo,
	)
	if err != nil {
		return BinaryMetadata{}, false
	}

	// Set ELF fields if it's an ELF binary
	if isELF.Valid && isELF.Bool {
		metadata.IsELF = true
		if elfType.Valid {
			metadata.ELFType = elfType.String
		}
		if architecture.Valid {
			metadata.Architecture = architecture.String
		}
		if interpreter.Valid {
			metadata.Interpreter = interpreter.String
		}
		if importSymCount.Valid {
			metadata.ImportedSymbolCount = int(importSymCount.Int64)
			metadata.ImportedSymbols = make([]string, 0)
		}
		if exportSymCount.Valid {
			metadata.ExportedSymbolCount = int(exportSymCount.Int64)
			metadata.ExportedSymbols = make([]string, 0)
		}
		if isStaticallyLinked.Valid {
			metadata.IsStaticallyLinked = isStaticallyLinked.Bool
		}
		if hasDebugInfo.Valid {
			metadata.HasDebugInfo = hasDebugInfo.Bool
		}

		// Parse imported libraries from JSON if needed
		if importedLibrariesJSON != "" {
			json.Unmarshal([]byte(importedLibrariesJSON), &metadata.ImportedLibraries)
		}
	}

	return metadata, true
}

// GetMetadataByPath retrieves binary metadata by its file path
func (a *analyzerImpl) GetMetadataByPath(path string) (BinaryMetadata, bool) {
	var metadata BinaryMetadata
	var importedLibrariesJSON, sectionsJSON sql.NullString
	var isELF, isStaticallyLinked, hasDebugInfo, isFromPackage, packageVerified sql.NullBool
	var elfType, architecture, interpreter, packageName, packageVersion, packageManager sql.NullString
	var importSymCount, exportSymCount sql.NullInt64

	// Using global DB connection
	err := globalDB.QueryRow(`
        SELECT md5_hash, sha256_hash, file_size, mod_time, first_seen,
               is_elf, elf_type, architecture, interpreter, 
               imported_libraries, imported_symbols_count, exported_symbols_count,
               is_statically_linked, sections, has_debug_info,
               is_from_package, package_name, package_version, package_verified, package_manager
        FROM binaries
        WHERE path = ?
    `, path).Scan(
		&metadata.MD5Hash,
		&metadata.SHA256Hash,
		&metadata.FileSize,
		&metadata.ModTime,
		&metadata.FirstSeen,
		&isELF,
		&elfType,
		&architecture,
		&interpreter,
		&importedLibrariesJSON,
		&importSymCount,
		&exportSymCount,
		&isStaticallyLinked,
		&sectionsJSON,
		&hasDebugInfo,
		&isFromPackage,
		&packageName,
		&packageVersion,
		&packageVerified,
		&packageManager,
	)
	if err != nil {
		return BinaryMetadata{}, false
	}

	// Set path
	metadata.Path = path

	// Handle ELF fields
	if isELF.Valid && isELF.Bool {
		metadata.IsELF = true
		if elfType.Valid {
			metadata.ELFType = elfType.String
		}
		if architecture.Valid {
			metadata.Architecture = architecture.String
		}
		if interpreter.Valid {
			metadata.Interpreter = interpreter.String
		}

		// Parse imported libraries from JSON
		if importedLibrariesJSON.Valid && importedLibrariesJSON.String != "" {
			json.Unmarshal([]byte(importedLibrariesJSON.String), &metadata.ImportedLibraries)
		} else {
			metadata.ImportedLibraries = []string{}
		}

		if importSymCount.Valid {
			metadata.ImportedSymbolCount = int(importSymCount.Int64)
		}
		if exportSymCount.Valid {
			metadata.ExportedSymbolCount = int(exportSymCount.Int64)
		}
		if isStaticallyLinked.Valid {
			metadata.IsStaticallyLinked = isStaticallyLinked.Bool
		}
		if hasDebugInfo.Valid {
			metadata.HasDebugInfo = hasDebugInfo.Bool
		}
	}

	// Set package information
	if isFromPackage.Valid {
		metadata.IsFromPackage = isFromPackage.Bool
	}
	if packageName.Valid {
		metadata.PackageName = packageName.String
	}
	if packageVersion.Valid {
		metadata.PackageVersion = packageVersion.String
	}
	if packageVerified.Valid {
		metadata.PackageVerified = packageVerified.Bool
	}
	if packageManager.Valid {
		metadata.PackageManager = packageManager.String
	}

	return metadata, true
}

// Implement the SetNewBinaryCallback method
func (a *analyzerImpl) SetNewBinaryCallback(callback func(BinaryMetadata)) {
	a.newBinaryCallback = callback
}

// Close properly closes the global database connection
// Since there's only one analyzer instance in the application, this is appropriate
func (a *analyzerImpl) Close() error {
	initMutex.Lock()
	defer initMutex.Unlock()

	if initialized && globalDB != nil {
		err := globalDB.Close()
		globalDB = nil
		initialized = false
		return err
	}

	return nil
}

// Helper functions
func elfInfoValue(info *ELFInfo, field string) interface{} {
	if info == nil {
		switch field {
		case "Type", "Architecture", "Interpreter":
			return ""
		default:
			return nil
		}
	}

	switch field {
	case "Type":
		return info.Type
	case "Architecture":
		return info.Architecture
	case "Interpreter":
		return info.Interpreter
	default:
		return nil
	}
}

func elfInfoBool(info *ELFInfo, field string) bool {
	if info == nil {
		return false
	}

	switch field {
	case "IsStaticallyLinked":
		return info.IsStaticallyLinked
	case "HasDebugInfo":
		return info.HasDebugInfo
	default:
		return false
	}
}

func getElfLibraries(info *ELFInfo) []string {
	if info == nil {
		return []string{}
	}
	return info.ImportedLibraries
}

// isLinuxExecutable checks if a file might be a Linux executable by looking at its header
func isLinuxExecutable(path string) bool {
	// Open the file
	file, err := os.Open(path)
	if err != nil {
		return false
	}
	defer file.Close()

	// Read the first 4 bytes (ELF magic number)
	magic := make([]byte, 4)
	if _, err := file.Read(magic); err != nil {
		return false
	}

	// Check for ELF magic number
	return bytes.Equal(magic, []byte{0x7F, 'E', 'L', 'F'})
}
