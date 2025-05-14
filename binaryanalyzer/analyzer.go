package binaryanalyzer

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// analyzerImpl implements the BinaryAnalyzer interface
type analyzerImpl struct {
	db                *sql.DB
	logger            Logger
	newBinaryCallback func(BinaryMetadata)
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

	var elfInfo *ELFInfo
	isELF := false
	if isLinuxExecutable(path) {
		if info, err := AnalyzeELF(path); err == nil {
			isELF = true
			elfInfo = info
			a.logger.Info("binary", "ELF analysis successful for %s: %s %s", path, info.Type, info.Architecture)
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

	// Convert arrays to JSON for storage
	var librariesJSON, sectionsJSON string
	// Get symbol counts for storage
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

		// In the future, we may want to store the most important symbols
		// rather than just counts, to use in fingerprinting and vector embeddings.
		// We will then use these for binary similarity search.
	} else {
		// Default empty arrays for non-ELF binaries
		librariesJSON = "[]"
		sectionsJSON = "[]"
		importedSymbolCount = 0
		exportedSymbolCount = 0
	}

	// We don't have UPSERT in limbo yet so need to use check-then-insert pattern
	// Check if the record already exists
	var exists bool
	err = a.db.QueryRow("SELECT 1 FROM binaries WHERE md5_hash = ? LIMIT 1", md5Hash).Scan(&exists)
	now := time.Now()

	// Later, we'll add code here to:
	// 1. Generate a vector embedding from the binary features
	// 2. Perform similarity search to find related binaries
	// 3. Store the embedding and similarity info in the database

	// If the record doesn't exist or there was an error (no rows), insert it
	if err == sql.ErrNoRows || !exists {

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

		// Perform INSERT
		_, err = a.db.Exec(`
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

		if a.newBinaryCallback != nil {
			// Create metadata object from our findings
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
				ImportedLibraries:   elfInfo.ImportedLibraries,
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

			// Call the callback with metadata
			a.newBinaryCallback(metadata)
		}

	} else {
		// Perform UPDATE
		_, err = a.db.Exec(`
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

	err := a.db.QueryRow(`
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
			// We don't store all symbols in DB, just the count
			metadata.ImportedSymbols = make([]string, 0)
		}
		if exportSymCount.Valid {
			// We don't store all symbols in DB, just the count
			metadata.ExportedSymbols = make([]string, 0)
		}
		if isStaticallyLinked.Valid {
			metadata.IsStaticallyLinked = isStaticallyLinked.Bool
		}
		if hasDebugInfo.Valid {
			metadata.HasDebugInfo = hasDebugInfo.Bool
		}

		// Parse imported libraries from JSON
		if importSymCount.Valid {
			metadata.ImportedSymbolCount = int(importSymCount.Int64)
			// later we'll store actual symbols for fingerprinting
			metadata.ImportedSymbols = make([]string, 0)
		}
		if exportSymCount.Valid {
			metadata.ExportedSymbolCount = int(exportSymCount.Int64)
			// later we'll store actual symbols for fingerprinting
			metadata.ExportedSymbols = make([]string, 0)
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

	err := a.db.QueryRow(`
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
		a.logger.Error("binary", "Error retrieving metadata for %s: %v", path, err)
		return BinaryMetadata{}, false
	}

	// Set path
	metadata.Path = path

	// Set ELF fields if it's an ELF binary
	if isELF.Valid && isELF.Bool {
		metadata.IsELF = true

		a.logger.Debug("binary", "Retrieved ELF binary info for %s", path)

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

		// Set imported/exported symbol counts
		if importSymCount.Valid {
			metadata.ImportedSymbolCount = int(importSymCount.Int64)
			// Later, we'll store actual symbols for fingerprinting
			metadata.ImportedSymbols = make([]string, 0)
		}
		if exportSymCount.Valid {
			metadata.ExportedSymbolCount = int(exportSymCount.Int64)
			// Later, we'll store actual symbols for fingerprinting
			metadata.ExportedSymbols = make([]string, 0)
		}

		// Set other boolean flags
		if isStaticallyLinked.Valid {
			metadata.IsStaticallyLinked = isStaticallyLinked.Bool
		}
		if hasDebugInfo.Valid {
			metadata.HasDebugInfo = hasDebugInfo.Bool
		}

		// Parse sections from JSON
		if sectionsJSON.Valid && sectionsJSON.String != "" {
			json.Unmarshal([]byte(sectionsJSON.String), &metadata.Sections)
		} else {
			metadata.Sections = []string{}
		}

	} else {
		a.logger.Debug("binary", "Retrieved non-ELF binary info for %s", path)
		metadata.IsELF = false
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

// Close closes the database connection
func (a *analyzerImpl) Close() error {
	return a.db.Close()
}

// Helper functions to safely access ELF info
func elfInfoValue(info *ELFInfo, field string) interface{} {
	if info == nil {
		return nil
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

func elfInfoCount(info *ELFInfo, field string) int {
	if info == nil {
		return 0
	}

	switch field {
	case "ImportedSymbols":
		return len(info.ImportedSymbols)
	case "ExportedSymbols":
		return len(info.ExportedSymbols)
	default:
		return 0
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

// Function to safely convert to JSON
func toJSON(data []string) string {
	if data == nil || len(data) == 0 {
		return "[]"
	}

	jsonData, err := json.Marshal(data)
	if err != nil {
		return "[]"
	}

	return string(jsonData)
}

// isLinuxExecutable checks if a file might be a Linux executable by looking at its header
func isLinuxExecutable(path string) bool {
	// Open the file
	file, err := os.Open(path)
	if err != nil {
		fmt.Printf("DEBUG: Error opening file for ELF check: %v\n", err)
		return false
	}
	defer file.Close()

	// Read the first 4 bytes (ELF magic number)
	magic := make([]byte, 4)
	if _, err := file.Read(magic); err != nil {
		fmt.Printf("DEBUG: Error reading magic bytes: %v\n", err)
		return false
	}

	// Check for ELF magic number and print it for debugging
	elfMagic := bytes.Equal(magic, []byte{0x7F, 'E', 'L', 'F'})
	fmt.Printf("DEBUG: File %s, Magic bytes: [%x %x %x %x], Is ELF: %v\n",
		path, magic[0], magic[1], magic[2], magic[3], elfMagic)

	return elfMagic
}
