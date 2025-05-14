package binaryanalyzer

import (
	"database/sql"
)

// initBinarySchema creates the database tables for binary metadata
func initBinarySchema(db *sql.DB) error {
	_, err := db.Exec(`
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
    );

    CREATE INDEX IF NOT EXISTS idx_binary_md5 ON binaries(md5_hash);
    CREATE INDEX IF NOT EXISTS idx_binary_path ON binaries(path);
    `)

	return err
}

/*
Later we'll extend this schema to support vector embeddings for similarity search:

CREATE TABLE IF NOT EXISTS binary_embeddings (
    md5_hash TEXT NOT NULL PRIMARY KEY,
    embedding BLOB NOT NULL,        -- Vector embedding as binary data
    embedding_version INTEGER,      -- Version of embedding algorithm
    features TEXT,                  -- JSON description of features used
    embedding_time DATETIME         -- When the embedding was generated
);

CREATE TABLE IF NOT EXISTS binary_similarities (
    source_hash TEXT NOT NULL,
    target_hash TEXT NOT NULL,
    similarity_score REAL NOT NULL, -- 0.0 to 1.0
    PRIMARY KEY (source_hash, target_hash)
);
*/
