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
		analyzed BOOLEAN DEFAULT 0
	);

	CREATE INDEX IF NOT EXISTS idx_binary_md5 ON binaries(md5_hash);
	CREATE INDEX IF NOT EXISTS idx_binary_path ON binaries(path);
	`)

	return err
}
