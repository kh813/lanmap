package db

import (
	"database/sql"
	"strconv"
)

// GetSetting retrieves a setting value by key
func (db *DB) GetSetting(key string) (string, error) {
	row := db.QueryRow("SELECT value FROM settings WHERE key = ?", key)
	var val string
	err := row.Scan(&val)
	if err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", err
	}
	return val, nil
}

// SetSetting sets or updates a setting key-value pair
func (db *DB) SetSetting(key, value string) error {
	_, err := db.Exec("INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value", key, value)
	return err
}

// GetAllSettings returns all settings as a map
func (db *DB) GetAllSettings() (map[string]string, error) {
	rows, err := db.Query("SELECT key, value FROM settings")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	settings := make(map[string]string)
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		settings[k] = v
	}
	return settings, rows.Err()
}

// GetRetentionDays returns retention days configured in settings (default: 90, 0 means disabled)
func (db *DB) GetRetentionDays() (int, error) {
	val, err := db.GetSetting("retention_days")
	if err != nil {
		return 90, err
	}
	if val == "" {
		return 90, nil
	}
	days, err := strconv.Atoi(val)
	if err != nil {
		return 90, nil
	}
	return days, nil
}

// SetRetentionDays updates the retention_days setting
func (db *DB) SetRetentionDays(days int) error {
	return db.SetSetting("retention_days", strconv.Itoa(days))
}

// IsPortScanEnabled returns whether active TCP port scanning is enabled during background scans.
// Defaults to false (Safe Mode) to avoid triggering IDS / firewalls (port scan warnings).
func (db *DB) IsPortScanEnabled() (bool, error) {
	val, err := db.GetSetting("port_scan_enabled")
	if err != nil {
		return false, err
	}
	return val == "true" || val == "1", nil
}

// SetPortScanEnabled updates the port_scan_enabled setting
func (db *DB) SetPortScanEnabled(enabled bool) error {
	val := "false"
	if enabled {
		val = "true"
	}
	return db.SetSetting("port_scan_enabled", val)
}

