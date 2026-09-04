package db

import (
	"bytes"
	"encoding/csv"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// CustomPort represents a monitored port rule per OS profile
type CustomPort struct {
	ID           int64     `json:"id"`
	ProfileID    string    `json:"profile_id"`
	Protocol     string    `json:"protocol"`
	Port         int       `json:"port"`
	ProtocolName string    `json:"protocol_name"`
	Description  string    `json:"description"`
	IsEnabled    bool      `json:"is_enabled"`
	IsBuiltin    bool      `json:"is_builtin"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// DefaultBuiltinPort defines an initial preset port
type DefaultBuiltinPort struct {
	ProfileID    string
	Protocol     string
	Port         int
	ProtocolName string
	Description  string
}

// BuiltinDefaultPorts lists all pre-configured ports per device profile
var BuiltinDefaultPorts = []DefaultBuiltinPort{
	// apple_mac
	{"apple_mac", "TCP", 22, "SSH (リモートログイン)", "Mac リモートログイン"},
	{"apple_mac", "TCP", 80, "HTTP", "Web サービス"},
	{"apple_mac", "TCP", 443, "HTTPS", "SSL/TLS Web サービス"},
	{"apple_mac", "TCP", 445, "SMB (ファイル共有)", "Windows/Mac ファイル共有"},
	{"apple_mac", "TCP", 548, "AFP (Mac共有)", "Apple Filing Protocol"},
	{"apple_mac", "TCP", 5900, "VNC (画面共有)", "Mac 画面共有"},
	{"apple_mac", "TCP", 5938, "TeamViewer", "遠隔操作ソフトウェア (緊急監視)"},
	{"apple_mac", "TCP", 7070, "AnyDesk", "遠隔操作ソフトウェア (緊急監視)"},

	// windows
	{"windows", "TCP", 80, "HTTP", "Web サービス"},
	{"windows", "TCP", 443, "HTTPS", "SSL/TLS Web サービス"},
	{"windows", "TCP", 445, "SMB (ファイル共有)", "Windows ファイル共有"},
	{"windows", "TCP", 1723, "PPTP VPN", "PPTP VPN サーバー"},
	{"windows", "TCP", 3389, "RDP (リモートデスクトップ)", "Windows リモートデスクトップ"},
	{"windows", "TCP", 5555, "SoftEther VPN", "SoftEther VPN サーバー"},
	{"windows", "TCP", 5900, "VNC", "VNC 画面共有"},
	{"windows", "TCP", 5938, "TeamViewer", "遠隔操作ソフトウェア (緊急監視)"},
	{"windows", "TCP", 7070, "AnyDesk", "遠隔操作ソフトウェア (緊急監視)"},

	// printer
	{"printer", "TCP", 80, "HTTP (管理画面)", "プリンタ Web 設定画面"},
	{"printer", "TCP", 443, "HTTPS (管理画面)", "プリンタ HTTPS 設定画面"},
	{"printer", "TCP", 631, "IPP (プリンタ)", "IPP 印刷プロトコル"},
	{"printer", "TCP", 9100, "RAW プリンタ", "RAW ダイレクト印刷"},

	// network
	{"network", "TCP", 22, "SSH", "ルーター/スイッチ 管理コンソール"},
	{"network", "TCP", 53, "DNS", "DNS サーバー"},
	{"network", "TCP", 80, "HTTP", "ルーター/スイッチ Web 管理画面"},
	{"network", "TCP", 443, "HTTPS", "ルーター/スイッチ HTTPS 管理画面"},
	{"network", "TCP", 8080, "HTTP-Alt", "代替 Web 管理ポート"},
	{"network", "TCP", 8443, "HTTPS-Alt", "代替 HTTPS 管理ポート"},

	// nas_linux
	{"nas_linux", "TCP", 22, "SSH", "Linux/NAS リモートシェル"},
	{"nas_linux", "TCP", 80, "HTTP", "Web サービス / 管理画面"},
	{"nas_linux", "TCP", 443, "HTTPS", "HTTPS サービス / 管理画面"},
	{"nas_linux", "TCP", 445, "SMB (ファイル共有)", "Samba ファイル共有"},
	{"nas_linux", "TCP", 1194, "OpenVPN", "OpenVPN サーバー"},
	{"nas_linux", "TCP", 5000, "Synology DSM / UPnP", "Synology DSM Web 管理画面"},
	{"nas_linux", "TCP", 5001, "Synology DSM (HTTPS)", "Synology DSM HTTPS 管理画面"},
	{"nas_linux", "TCP", 5555, "SoftEther VPN", "SoftEther VPN サーバー"},
	{"nas_linux", "TCP", 5900, "VNC", "VNC リモートデスクトップ"},
	{"nas_linux", "TCP", 8080, "HTTP-Alt", "Web アプリケーションポート"},
	{"nas_linux", "TCP", 8443, "HTTPS-Alt", "HTTPS アプリケーションポート"},

	// media_iot
	{"media_iot", "TCP", 80, "HTTP", "IoT 機器 Web 管理画面"},
	{"media_iot", "TCP", 443, "HTTPS", "IoT 機器 HTTPS サービス"},
	{"media_iot", "TCP", 554, "RTSP (カメラ)", "ネットワークカメラ RTSP 配信"},
	{"media_iot", "TCP", 8008, "Google Cast", "Google Cast 待受ポート"},

	// generic
	{"generic", "TCP", 22, "SSH", "SSH サービス"},
	{"generic", "TCP", 80, "HTTP", "HTTP Web サービス"},
	{"generic", "TCP", 443, "HTTPS", "HTTPS サービス"},
	{"generic", "TCP", 445, "SMB (ファイル共有)", "SMB ファイル共有"},
	{"generic", "TCP", 1194, "OpenVPN", "OpenVPN 待受"},
	{"generic", "TCP", 1723, "PPTP VPN", "PPTP VPN 待受"},
	{"generic", "TCP", 3389, "RDP (リモートデスクトップ)", "リモートデスクトップ"},
	{"generic", "TCP", 5555, "SoftEther VPN", "SoftEther VPN 待受"},
	{"generic", "TCP", 5900, "VNC", "VNC 画面共有"},
	{"generic", "TCP", 5938, "TeamViewer", "遠隔操作ソフトウェア (緊急監視)"},
	{"generic", "TCP", 7070, "AnyDesk", "遠隔操作ソフトウェア (緊急監視)"},
}

// SeedDefaultCustomPorts inserts default built-in ports if table is empty
func (db *DB) SeedDefaultCustomPorts() error {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM custom_profile_ports").Scan(&count)
	if err != nil {
		return fmt.Errorf("failed to check custom_profile_ports count: %w", err)
	}
	if count > 0 {
		return nil
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	stmt, err := tx.Prepare(`
		INSERT INTO custom_profile_ports (profile_id, protocol, port, protocol_name, description, is_enabled, is_builtin)
		VALUES (?, ?, ?, ?, ?, 1, 1)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, p := range BuiltinDefaultPorts {
		if _, err := stmt.Exec(p.ProfileID, p.Protocol, p.Port, p.ProtocolName, p.Description); err != nil {
			return fmt.Errorf("failed to seed custom port %s:%d: %w", p.ProfileID, p.Port, err)
		}
	}

	return tx.Commit()
}

// ResetCustomPortsToDefault deletes all custom profile ports and re-seeds the built-in defaults
func (db *DB) ResetCustomPortsToDefault() error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.Exec("DELETE FROM custom_profile_ports"); err != nil {
		return fmt.Errorf("failed to clear custom_profile_ports: %w", err)
	}

	stmt, err := tx.Prepare(`
		INSERT INTO custom_profile_ports (profile_id, protocol, port, protocol_name, description, is_enabled, is_builtin)
		VALUES (?, ?, ?, ?, ?, 1, 1)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, p := range BuiltinDefaultPorts {
		if _, err := stmt.Exec(p.ProfileID, p.Protocol, p.Port, p.ProtocolName, p.Description); err != nil {
			return fmt.Errorf("failed to seed custom port %s:%d: %w", p.ProfileID, p.Port, err)
		}
	}

	return tx.Commit()
}

// ListCustomPorts retrieves ports filtered by profileID (if not empty or "all_profiles")
func (db *DB) ListCustomPorts(profileID string) ([]*CustomPort, error) {
	var query string
	var args []interface{}

	if profileID != "" && profileID != "all_profiles" {
		query = `
			SELECT id, profile_id, protocol, port, protocol_name, description, is_enabled, is_builtin, created_at, updated_at
			FROM custom_profile_ports
			WHERE profile_id = ?
			ORDER BY port ASC, protocol ASC
		`
		args = append(args, profileID)
	} else {
		query = `
			SELECT id, profile_id, protocol, port, protocol_name, description, is_enabled, is_builtin, created_at, updated_at
			FROM custom_profile_ports
			ORDER BY 
				CASE profile_id
					WHEN 'all' THEN 1
					WHEN 'apple_mac' THEN 2
					WHEN 'windows' THEN 3
					WHEN 'nas_linux' THEN 4
					WHEN 'printer' THEN 5
					WHEN 'network' THEN 6
					WHEN 'media_iot' THEN 7
					WHEN 'generic' THEN 8
					ELSE 9
				END,
				port ASC
		`
	}

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, fmt.Errorf("failed to query custom ports: %w", err)
	}
	defer rows.Close()

	var ports []*CustomPort
	for rows.Next() {
		var p CustomPort
		var desc sqlNullStringCustom
		if err := rows.Scan(
			&p.ID,
			&p.ProfileID,
			&p.Protocol,
			&p.Port,
			&p.ProtocolName,
			&desc,
			&p.IsEnabled,
			&p.IsBuiltin,
			&p.CreatedAt,
			&p.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan custom port: %w", err)
		}
		p.Description = desc.String
		ports = append(ports, &p)
	}

	return ports, nil
}

type sqlNullStringCustom struct {
	String string
	Valid  bool
}

func (s *sqlNullStringCustom) Scan(value interface{}) error {
	if value == nil {
		s.String, s.Valid = "", false
		return nil
	}
	switch v := value.(type) {
	case string:
		s.String, s.Valid = v, true
	case []byte:
		s.String, s.Valid = string(v), true
	default:
		s.String, s.Valid = fmt.Sprintf("%v", v), true
	}
	return nil
}

// GetCustomPort retrieves a single custom port by ID
func (db *DB) GetCustomPort(id int64) (*CustomPort, error) {
	query := `
		SELECT id, profile_id, protocol, port, protocol_name, description, is_enabled, is_builtin, created_at, updated_at
		FROM custom_profile_ports
		WHERE id = ?
	`
	var p CustomPort
	var desc sqlNullStringCustom
	err := db.QueryRow(query, id).Scan(
		&p.ID,
		&p.ProfileID,
		&p.Protocol,
		&p.Port,
		&p.ProtocolName,
		&desc,
		&p.IsEnabled,
		&p.IsBuiltin,
		&p.CreatedAt,
		&p.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("custom port not found: %w", err)
	}
	p.Description = desc.String
	return &p, nil
}

// CreateCustomPort inserts a new custom port
func (db *DB) CreateCustomPort(p *CustomPort) error {
	if p.Port < 1 || p.Port > 65535 {
		return fmt.Errorf("invalid port number: %d", p.Port)
	}
	if p.Protocol == "" {
		p.Protocol = "TCP"
	} else {
		p.Protocol = strings.ToUpper(strings.TrimSpace(p.Protocol))
	}
	if p.ProfileID == "" {
		p.ProfileID = "all"
	}
	p.ProtocolName = strings.TrimSpace(p.ProtocolName)
	if p.ProtocolName == "" {
		p.ProtocolName = fmt.Sprintf("Port %d", p.Port)
	}

	query := `
		INSERT INTO custom_profile_ports (profile_id, protocol, port, protocol_name, description, is_enabled, is_builtin, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
	`
	res, err := db.Exec(query, p.ProfileID, p.Protocol, p.Port, p.ProtocolName, p.Description, p.IsEnabled, p.IsBuiltin)
	if err != nil {
		return fmt.Errorf("failed to create custom port: %w", err)
	}

	id, err := res.LastInsertId()
	if err == nil {
		p.ID = id
	}
	return nil
}

// UpdateCustomPort updates an existing port's metadata
func (db *DB) UpdateCustomPort(id int64, profileID, protocol string, port int, name, description string, isEnabled bool) error {
	if port < 1 || port > 65535 {
		return fmt.Errorf("invalid port number: %d", port)
	}
	if protocol == "" {
		protocol = "TCP"
	} else {
		protocol = strings.ToUpper(strings.TrimSpace(protocol))
	}
	if profileID == "" {
		profileID = "all"
	}
	name = strings.TrimSpace(name)
	if name == "" {
		name = fmt.Sprintf("Port %d", port)
	}

	query := `
		UPDATE custom_profile_ports
		SET profile_id = ?, protocol = ?, port = ?, protocol_name = ?, description = ?, is_enabled = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`
	res, err := db.Exec(query, profileID, protocol, port, name, description, isEnabled, id)
	if err != nil {
		return fmt.Errorf("failed to update custom port: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("custom port not found")
	}
	return nil
}

// ToggleCustomPort flips the is_enabled status of a port
func (db *DB) ToggleCustomPort(id int64) (bool, error) {
	p, err := db.GetCustomPort(id)
	if err != nil {
		return false, err
	}
	newState := !p.IsEnabled
	query := `UPDATE custom_profile_ports SET is_enabled = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`
	if _, err := db.Exec(query, newState, id); err != nil {
		return false, fmt.Errorf("failed to toggle custom port: %w", err)
	}
	return newState, nil
}

// DeleteCustomPort deletes a port by ID
func (db *DB) DeleteCustomPort(id int64) error {
	query := `DELETE FROM custom_profile_ports WHERE id = ?`
	res, err := db.Exec(query, id)
	if err != nil {
		return fmt.Errorf("failed to delete custom port: %w", err)
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("custom port not found")
	}
	return nil
}

// GetActiveTargetPortsForProfile returns map of active port -> service name for the given profile + 'all'
func (db *DB) GetActiveTargetPortsForProfile(profile string) (map[int]string, error) {
	query := `
		SELECT port, protocol_name
		FROM custom_profile_ports
		WHERE is_enabled = 1 AND (profile_id = ? OR profile_id = 'all')
		ORDER BY port ASC
	`
	rows, err := db.Query(query, profile)
	if err != nil {
		return nil, fmt.Errorf("failed to query active target ports: %w", err)
	}
	defer rows.Close()

	res := make(map[int]string)
	for rows.Next() {
		var port int
		var name string
		if err := rows.Scan(&port, &name); err == nil {
			res[port] = name
		}
	}
	return res, nil
}

// ExportCustomPortsCSV exports all custom ports as a CSV string
func (db *DB) ExportCustomPortsCSV() (string, error) {
	ports, err := db.ListCustomPorts("")
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	w := csv.NewWriter(&buf)

	// Header
	header := []string{"TargetOS", "Protocol", "Port", "ProtocolName", "Description", "Enabled"}
	if err := w.Write(header); err != nil {
		return "", err
	}

	for _, p := range ports {
		row := []string{
			p.ProfileID,
			p.Protocol,
			strconv.Itoa(p.Port),
			p.ProtocolName,
			p.Description,
			strconv.FormatBool(p.IsEnabled),
		}
		if err := w.Write(row); err != nil {
			return "", err
		}
	}

	w.Flush()
	if err := w.Error(); err != nil {
		return "", err
	}

	return buf.String(), nil
}

// ImportCustomPortsCSV imports ports from CSV content.
// If replace is true, existing ports are deleted first.
// If replace is false, entries are upserted based on (profile_id, protocol, port).
func (db *DB) ImportCustomPortsCSV(csvData string, replace bool) (int, error) {
	r := csv.NewReader(strings.NewReader(csvData))
	r.TrimLeadingSpace = true

	records, err := r.ReadAll()
	if err != nil {
		return 0, fmt.Errorf("failed to parse CSV: %w", err)
	}

	if len(records) == 0 {
		return 0, fmt.Errorf("CSV is empty")
	}

	// Determine header positions
	headerRow := records[0]
	targetOSIdx, protoIdx, portIdx, nameIdx, descIdx, enabledIdx := -1, -1, -1, -1, -1, -1

	for i, col := range headerRow {
		c := strings.ToLower(strings.TrimSpace(col))
		switch c {
		case "targetos", "profile", "profile_id", "os":
			targetOSIdx = i
		case "protocol", "proto":
			protoIdx = i
		case "port", "port_number":
			portIdx = i
		case "protocolname", "name", "service", "protocol_name":
			nameIdx = i
		case "description", "desc", "note":
			descIdx = i
		case "enabled", "is_enabled":
			enabledIdx = i
		}
	}

	if portIdx == -1 {
		return 0, fmt.Errorf("CSV header must include 'Port' column")
	}

	tx, err := db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	if replace {
		if _, err := tx.Exec("DELETE FROM custom_profile_ports"); err != nil {
			return 0, fmt.Errorf("failed to clear table for replace import: %w", err)
		}
	}

	upsertStmt, err := tx.Prepare(`
		INSERT INTO custom_profile_ports (profile_id, protocol, port, protocol_name, description, is_enabled, is_builtin, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(profile_id, protocol, port) DO UPDATE SET
			protocol_name = excluded.protocol_name,
			description = excluded.description,
			is_enabled = excluded.is_enabled,
			updated_at = CURRENT_TIMESTAMP
	`)
	if err != nil {
		return 0, fmt.Errorf("failed to prepare upsert: %w", err)
	}
	defer upsertStmt.Close()

	count := 0
	for lineNum, row := range records[1:] {
		if len(row) <= portIdx || strings.TrimSpace(row[portIdx]) == "" {
			continue
		}

		portStr := strings.TrimSpace(row[portIdx])
		port, err := strconv.Atoi(portStr)
		if err != nil || port < 1 || port > 65535 {
			continue // Skip invalid port
		}

		profileID := "all"
		if targetOSIdx >= 0 && targetOSIdx < len(row) {
			val := strings.ToLower(strings.TrimSpace(row[targetOSIdx]))
			if val != "" {
				profileID = val
			}
		}

		protocol := "TCP"
		if protoIdx >= 0 && protoIdx < len(row) {
			val := strings.ToUpper(strings.TrimSpace(row[protoIdx]))
			if val == "UDP" {
				protocol = "UDP"
			}
		}

		name := fmt.Sprintf("Port %d", port)
		if nameIdx >= 0 && nameIdx < len(row) {
			val := strings.TrimSpace(row[nameIdx])
			if val != "" {
				name = val
			}
		}

		desc := ""
		if descIdx >= 0 && descIdx < len(row) {
			desc = strings.TrimSpace(row[descIdx])
		}

		enabled := true
		if enabledIdx >= 0 && enabledIdx < len(row) {
			val := strings.ToLower(strings.TrimSpace(row[enabledIdx]))
			if val == "false" || val == "0" || val == "no" || val == "off" {
				enabled = false
			}
		}

		if _, err := upsertStmt.Exec(profileID, protocol, port, name, desc, enabled); err != nil {
			return 0, fmt.Errorf("failed to import row %d: %w", lineNum+2, err)
		}
		count++
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}

	return count, nil
}
