package db

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

// DB wraps the sql.DB instance
type DB struct {
	*sql.DB
}

// Open initializes SQLite database, runs migrations and initial seeds
func Open(dbPath string) (*DB, error) {
	if err := os.MkdirAll(filepath.Dir(dbPath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create db directory: %w", err)
	}

	// Enable WAL mode, foreign keys, busy timeout
	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

	// Configure connection pool for SQLite
	db.SetMaxOpenConns(1)

	wrapped := &DB{DB: db}
	if err := wrapped.migrate(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	if err := wrapped.seed(); err != nil {
		db.Close()
		return nil, fmt.Errorf("failed to seed initial data: %w", err)
	}

	return wrapped, nil
}

func (db *DB) migrate() error {
	schema := `
	CREATE TABLE IF NOT EXISTS segments (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name VARCHAR(100) NOT NULL,
		cidr VARCHAR(45) NOT NULL,
		interface_name VARCHAR(50),
		is_enabled BOOLEAN DEFAULT 1,
		is_default BOOLEAN DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS hosts (
		ip VARCHAR(45) PRIMARY KEY,
		segment_id INTEGER,
		mac_address VARCHAR(17),
		hostname VARCHAR(255),
		vendor_model VARCHAR(255),
		display_name VARCHAR(255),
		os_vendor VARCHAR(255),
		status VARCHAR(10) DEFAULT 'up',
		is_approved BOOLEAN DEFAULT 0,
		is_protected BOOLEAN DEFAULT 0,
		is_static_ip BOOLEAN DEFAULT 0,
		is_monitored BOOLEAN DEFAULT 0,
		is_paused BOOLEAN DEFAULT 0,
		has_conflict BOOLEAN DEFAULT 0,
		kuma_name VARCHAR(255),
		uptime_kuma_id INTEGER DEFAULT NULL,
		first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_seen DATETIME,
		FOREIGN KEY (segment_id) REFERENCES segments(id) ON DELETE SET NULL
	);

	CREATE INDEX IF NOT EXISTS idx_hosts_segment_id ON hosts(segment_id);
	CREATE INDEX IF NOT EXISTS idx_hosts_status ON hosts(status);
	CREATE INDEX IF NOT EXISTS idx_hosts_mac ON hosts(mac_address);

	CREATE TABLE IF NOT EXISTS settings (
		key VARCHAR(50) PRIMARY KEY,
		value TEXT
	);
	`
	_, err := db.Exec(schema)
	return err
}

func (db *DB) seed() error {
	// Seed default "未分類" (Uncategorized) segment if it doesn't exist
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM segments WHERE is_default = 1").Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check default segment: %w", err)
	}
	if count == 0 {
		_, err = db.Exec("INSERT INTO segments (name, cidr, is_enabled, is_default) VALUES (?, ?, 1, 1)", "未分類", "")
		if err != nil {
			return fmt.Errorf("failed to insert default segment: %w", err)
		}
	}

	// Seed default retention_days if not set
	err = db.QueryRow("SELECT COUNT(*) FROM settings WHERE key = 'retention_days'").Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check retention_days setting: %w", err)
	}
	if count == 0 {
		_, err = db.Exec("INSERT INTO settings (key, value) VALUES ('retention_days', '180')")
		if err != nil {
			return fmt.Errorf("failed to seed default retention_days: %w", err)
		}
	}

	return nil
}
