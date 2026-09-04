package db

import (
	"database/sql"
	"fmt"
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

const (
	ScanModeStealth = "stealth" // Default: passive broadcast (DHCP/mDNS/SSDP) + Ping + ARP, zero active port probing
	ScanModeSafe    = "safe"    // Stealth + OS-tailored key ports
	ScanModeFull    = "full"    // Safe + broader range of 40+ ports
)

// GetScanMode returns the configured scan mode: "stealth", "safe", or "full".
// Defaults to "stealth".
func (db *DB) GetScanMode() (string, error) {
	val, err := db.GetSetting("scan_mode")
	if err == nil && val != "" {
		switch val {
		case ScanModeStealth, ScanModeSafe, ScanModeFull:
			return val, nil
		}
	}
	// Fallback to legacy port_scan_enabled if present
	legacy, err := db.GetSetting("port_scan_enabled")
	if err == nil && (legacy == "true" || legacy == "1") {
		return ScanModeFull, nil
	}
	return ScanModeStealth, nil
}

// SetScanMode updates the scan_mode setting and synchronizes port_scan_enabled for backwards compatibility.
func (db *DB) SetScanMode(mode string) error {
	switch mode {
	case ScanModeStealth, ScanModeSafe, ScanModeFull:
		if err := db.SetSetting("scan_mode", mode); err != nil {
			return err
		}
		legacyVal := "false"
		if mode == ScanModeFull {
			legacyVal = "true"
		}
		return db.SetSetting("port_scan_enabled", legacyVal)
	default:
		return fmt.Errorf("invalid scan mode: %s", mode)
	}
}

// IsPortScanEnabled returns whether active full TCP port scanning is enabled.
// Maintained for backwards compatibility.
func (db *DB) IsPortScanEnabled() (bool, error) {
	mode, err := db.GetScanMode()
	if err != nil {
		return false, err
	}
	return mode == ScanModeFull, nil
}

// SetPortScanEnabled updates port_scan_enabled and scan_mode for backwards compatibility
func (db *DB) SetPortScanEnabled(enabled bool) error {
	if enabled {
		return db.SetScanMode(ScanModeFull)
	}
	return db.SetScanMode(ScanModeStealth)
}

