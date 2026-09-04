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

	dsn := fmt.Sprintf("file:%s?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)", dbPath)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite database: %w", err)
	}

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
		dhcp_range VARCHAR(100) DEFAULT '',
		is_dhcp_manual BOOLEAN DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE TABLE IF NOT EXISTS hosts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		ip VARCHAR(45) NOT NULL,
		segment_id INTEGER,
		mac_address VARCHAR(17),
		hostname VARCHAR(255),
		vendor_model VARCHAR(255),
		display_name VARCHAR(255),
		os_vendor VARCHAR(255),
		status VARCHAR(10) DEFAULT 'up',
		ping_rtt_ms REAL,
		ping_jitter_ms REAL,
		uptime_pct REAL DEFAULT 100.0,
		open_ports TEXT,
		http_title VARCHAR(255),
		upnp_name VARCHAR(255),
		upnp_model VARCHAR(255),
		upnp_serial VARCHAR(100),
		tls_subject VARCHAR(255),
		tls_expiry DATETIME,
		mdns_model VARCHAR(100),
		broadcast_count_1m INTEGER DEFAULT 0,
		is_storming BOOLEAN DEFAULT 0,
		is_approved BOOLEAN DEFAULT 0,
		is_protected BOOLEAN DEFAULT 0,
		is_static_ip BOOLEAN DEFAULT 0,
		is_dhcp BOOLEAN DEFAULT 0,
		is_monitored BOOLEAN DEFAULT 0,
		is_paused BOOLEAN DEFAULT 0,
		has_conflict BOOLEAN DEFAULT 0,
		kuma_name VARCHAR(255),
		uptime_kuma_id INTEGER DEFAULT NULL,
		first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_seen DATETIME,
		last_port_scan DATETIME,
		next_port_scan DATETIME,
		ignored_ports TEXT DEFAULT '',
		FOREIGN KEY (segment_id) REFERENCES segments(id) ON DELETE SET NULL
	);

	CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip);
	CREATE INDEX IF NOT EXISTS idx_hosts_segment_id ON hosts(segment_id);
	CREATE INDEX IF NOT EXISTS idx_hosts_status ON hosts(status);
	CREATE INDEX IF NOT EXISTS idx_hosts_mac ON hosts(mac_address);
	CREATE INDEX IF NOT EXISTS idx_hosts_hostname ON hosts(hostname);
	CREATE INDEX IF NOT EXISTS idx_hosts_next_port_scan ON hosts(next_port_scan);

	CREATE TABLE IF NOT EXISTS settings (
		key VARCHAR(50) PRIMARY KEY,
		value TEXT
	);

	CREATE TABLE IF NOT EXISTS whitelist_entries (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		hostname VARCHAR(255),
		mac_address VARCHAR(17),
		serial_number VARCHAR(100),
		device_name VARCHAR(255),
		note TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_whitelist_hostname ON whitelist_entries(hostname);
	CREATE INDEX IF NOT EXISTS idx_whitelist_mac ON whitelist_entries(mac_address);

	CREATE TABLE IF NOT EXISTS ping_history (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		host_ip VARCHAR(45) NOT NULL,
		rtt_ms REAL,
		status VARCHAR(10) NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE INDEX IF NOT EXISTS idx_ping_history_ip_time ON ping_history(host_ip, created_at);

	CREATE TABLE IF NOT EXISTS custom_profile_ports (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		profile_id VARCHAR(50) NOT NULL,
		protocol VARCHAR(10) NOT NULL DEFAULT 'TCP',
		port INTEGER NOT NULL,
		protocol_name VARCHAR(100) NOT NULL,
		description TEXT DEFAULT '',
		is_enabled BOOLEAN DEFAULT 1,
		is_builtin BOOLEAN DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	);

	CREATE UNIQUE INDEX IF NOT EXISTS idx_profile_port_proto ON custom_profile_ports(profile_id, protocol, port);
	CREATE INDEX IF NOT EXISTS idx_profile_ports_lookup ON custom_profile_ports(profile_id, is_enabled);
	`
	if _, err := db.Exec(schema); err != nil {
		return err
	}

	// Check if hosts table has 'id' primary key column (migrate from legacy ip PRIMARY KEY)
	var hasID bool
	rows, err := db.Query("PRAGMA table_info(hosts)")
	if err == nil {
		for rows.Next() {
			var cid int
			var name, ctype string
			var notnull, pk int
			var dflt sql.NullString
			if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err == nil {
				if name == "id" {
					hasID = true
				}
			}
		}
		rows.Close()
	}

	if !hasID {
		// Table recreate migration for legacy schema
		migrateHostsSQL := `
		CREATE TABLE hosts_migration_tmp (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			ip VARCHAR(45) NOT NULL,
			segment_id INTEGER,
			mac_address VARCHAR(17),
			hostname VARCHAR(255),
			vendor_model VARCHAR(255),
			display_name VARCHAR(255),
			os_vendor VARCHAR(255),
			status VARCHAR(10) DEFAULT 'up',
			ping_rtt_ms REAL,
			ping_jitter_ms REAL,
			uptime_pct REAL DEFAULT 100.0,
			open_ports TEXT,
			http_title VARCHAR(255),
			upnp_name VARCHAR(255),
			upnp_model VARCHAR(255),
			upnp_serial VARCHAR(100),
			tls_subject VARCHAR(255),
			tls_expiry DATETIME,
			mdns_model VARCHAR(100),
			broadcast_count_1m INTEGER DEFAULT 0,
			is_storming BOOLEAN DEFAULT 0,
			is_approved BOOLEAN DEFAULT 0,
			is_protected BOOLEAN DEFAULT 0,
			is_static_ip BOOLEAN DEFAULT 0,
			is_dhcp BOOLEAN DEFAULT 0,
			is_monitored BOOLEAN DEFAULT 0,
			is_paused BOOLEAN DEFAULT 0,
			has_conflict BOOLEAN DEFAULT 0,
			kuma_name VARCHAR(255),
			uptime_kuma_id INTEGER DEFAULT NULL,
			first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
			last_seen DATETIME,
			last_port_scan DATETIME,
			next_port_scan DATETIME,
			ignored_ports TEXT DEFAULT '',
			FOREIGN KEY (segment_id) REFERENCES segments(id) ON DELETE SET NULL
		);

		INSERT INTO hosts_migration_tmp (
			ip, segment_id, mac_address, hostname, vendor_model, display_name,
			os_vendor, status, ping_rtt_ms, ping_jitter_ms, uptime_pct,
			open_ports, http_title, upnp_name, upnp_model, upnp_serial,
			tls_subject, tls_expiry, mdns_model, broadcast_count_1m, is_storming,
			is_approved, is_protected, is_static_ip, is_dhcp,
			is_monitored, is_paused, has_conflict, kuma_name, uptime_kuma_id,
			first_seen, last_seen, last_port_scan, next_port_scan, ignored_ports
		) SELECT
			ip, segment_id, mac_address, hostname, vendor_model, display_name,
			os_vendor, status, ping_rtt_ms, ping_jitter_ms, uptime_pct,
			open_ports, http_title, upnp_name, upnp_model, upnp_serial,
			tls_subject, tls_expiry, mdns_model, broadcast_count_1m, is_storming,
			is_approved, is_protected, is_static_ip, is_dhcp,
			is_monitored, is_paused, has_conflict, kuma_name, uptime_kuma_id,
			first_seen, last_seen, last_port_scan, next_port_scan, COALESCE(ignored_ports, '')
		FROM hosts;

		DROP TABLE hosts;
		ALTER TABLE hosts_migration_tmp RENAME TO hosts;
		`
		if _, err := db.Exec(migrateHostsSQL); err != nil {
			return fmt.Errorf("failed to migrate hosts table to id-based schema: %w", err)
		}
	}

	// Migrations for existing DBs
	_, _ = db.Exec("ALTER TABLE hosts ADD COLUMN ping_rtt_ms REAL;")
	_, _ = db.Exec("ALTER TABLE hosts ADD COLUMN ping_jitter_ms REAL;")
	_, _ = db.Exec("ALTER TABLE hosts ADD COLUMN uptime_pct REAL DEFAULT 100.0;")
	_, _ = db.Exec("ALTER TABLE hosts ADD COLUMN open_ports TEXT;")
	_, _ = db.Exec("ALTER TABLE hosts ADD COLUMN http_title VARCHAR(255);")
	_, _ = db.Exec("ALTER TABLE hosts ADD COLUMN upnp_name VARCHAR(255);")
	_, _ = db.Exec("ALTER TABLE hosts ADD COLUMN upnp_model VARCHAR(255);")
	_, _ = db.Exec("ALTER TABLE hosts ADD COLUMN upnp_serial VARCHAR(100);")
	_, _ = db.Exec("ALTER TABLE hosts ADD COLUMN tls_subject VARCHAR(255);")
	_, _ = db.Exec("ALTER TABLE hosts ADD COLUMN tls_expiry DATETIME;")
	_, _ = db.Exec("ALTER TABLE hosts ADD COLUMN mdns_model VARCHAR(100);")
	_, _ = db.Exec("ALTER TABLE hosts ADD COLUMN broadcast_count_1m INTEGER DEFAULT 0;")
	_, _ = db.Exec("ALTER TABLE hosts ADD COLUMN is_storming BOOLEAN DEFAULT 0;")
	_, _ = db.Exec("ALTER TABLE hosts ADD COLUMN is_dhcp BOOLEAN DEFAULT 0;")
	_, _ = db.Exec("ALTER TABLE hosts ADD COLUMN last_port_scan DATETIME;")
	_, _ = db.Exec("ALTER TABLE hosts ADD COLUMN next_port_scan DATETIME;")
	_, _ = db.Exec("ALTER TABLE hosts ADD COLUMN ignored_ports TEXT DEFAULT '';")
	_, _ = db.Exec("CREATE INDEX IF NOT EXISTS idx_hosts_ip ON hosts(ip);")
	_, _ = db.Exec("CREATE INDEX IF NOT EXISTS idx_hosts_next_port_scan ON hosts(next_port_scan);")
	_, _ = db.Exec("ALTER TABLE segments ADD COLUMN dhcp_range VARCHAR(100) DEFAULT '';")
	_, _ = db.Exec("ALTER TABLE segments ADD COLUMN is_dhcp_manual BOOLEAN DEFAULT 0;")

	return nil
}

func (db *DB) seed() error {
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

	err = db.QueryRow("SELECT COUNT(*) FROM settings WHERE key = 'retention_days'").Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check retention_days setting: %w", err)
	}
	if count == 0 {
		_, err = db.Exec("INSERT INTO settings (key, value) VALUES ('retention_days', '3')")
		if err != nil {
			return fmt.Errorf("failed to seed default retention_days: %w", err)
		}
	} else {
		// Update default retention_days from legacy "90" to "3" if it was unmodified
		var currentRetention string
		if err := db.QueryRow("SELECT value FROM settings WHERE key = 'retention_days'").Scan(&currentRetention); err == nil {
			if currentRetention == "90" {
				_, _ = db.Exec("UPDATE settings SET value = '3' WHERE key = 'retention_days'")
			}
		}
	}

	if err := db.SeedDefaultCustomPorts(); err != nil {
		return fmt.Errorf("failed to seed default custom ports: %w", err)
	}

	return nil
}
