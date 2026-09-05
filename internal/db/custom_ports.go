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
	Severity     string    `json:"severity"` // "info", "warning", "danger"
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
	Severity     string // "info", "warning", "danger"
}

// BuiltinDefaultPorts lists all pre-configured ports per device profile
var BuiltinDefaultPorts = []DefaultBuiltinPort{
	// apple_mac
	{"apple_mac", "TCP", 22, "SSH (リモートログイン)", "Mac リモートログイン", "info"},
	{"apple_mac", "TCP", 80, "HTTP", "Web サービス", "info"},
	{"apple_mac", "TCP", 443, "HTTPS", "SSL/TLS Web サービス", "info"},
	{"apple_mac", "TCP", 445, "SMB (ファイル共有)", "Windows/Mac ファイル共有", "info"},
	{"apple_mac", "TCP", 548, "AFP (Mac共有)", "Apple Filing Protocol", "info"},
	{"apple_mac", "TCP", 5900, "VNC (画面共有)", "Mac 画面共有", "warning"},
	{"apple_mac", "TCP", 5938, "TeamViewer", "遠隔操作ソフトウェア (緊急監視)", "danger"},
	{"apple_mac", "TCP", 7070, "AnyDesk", "遠隔操作ソフトウェア (緊急監視)", "danger"},

	// windows
	{"windows", "TCP", 80, "HTTP", "Web サービス", "info"},
	{"windows", "TCP", 443, "HTTPS", "SSL/TLS Web サービス", "info"},
	{"windows", "TCP", 445, "SMB (ファイル共有)", "Windows ファイル共有", "info"},
	{"windows", "TCP", 1723, "PPTP VPN", "PPTP VPN サーバー", "danger"},
	{"windows", "TCP", 3389, "RDP (リモートデスクトップ)", "Windows リモートデスクトップ", "warning"},
	{"windows", "TCP", 5555, "SoftEther VPN", "SoftEther VPN サーバー", "danger"},
	{"windows", "TCP", 5900, "VNC", "VNC 画面共有", "warning"},
	{"windows", "TCP", 5938, "TeamViewer", "遠隔操作ソフトウェア (緊急監視)", "danger"},
	{"windows", "TCP", 7070, "AnyDesk", "遠隔操作ソフトウェア (緊急監視)", "danger"},

	// printer
	{"printer", "TCP", 80, "HTTP (管理画面)", "プリンタ Web 設定画面", "info"},
	{"printer", "TCP", 443, "HTTPS (管理画面)", "プリンタ HTTPS 設定画面", "info"},
	{"printer", "TCP", 631, "IPP (プリンタ)", "IPP 印刷プロトコル", "info"},
	{"printer", "TCP", 9100, "RAW プリンタ", "RAW ダイレクト印刷", "info"},

	// network
	{"network", "TCP", 22, "SSH", "ルーター/スイッチ 管理コンソール", "info"},
	{"network", "TCP", 53, "DNS", "DNS サーバー", "info"},
	{"network", "TCP", 80, "HTTP", "ルーター/スイッチ Web 管理画面", "info"},
	{"network", "TCP", 443, "HTTPS", "ルーター/スイッチ HTTPS 管理画面", "info"},
	{"network", "TCP", 8080, "HTTP-Alt", "代替 Web 管理ポート", "info"},
	{"network", "TCP", 8443, "HTTPS-Alt", "代替 HTTPS 管理ポート", "info"},

	// nas_linux
	{"nas_linux", "TCP", 22, "SSH", "Linux/NAS リモートシェル", "info"},
	{"nas_linux", "TCP", 80, "HTTP", "Web サービス / 管理画面", "info"},
	{"nas_linux", "TCP", 443, "HTTPS", "HTTPS サービス / 管理画面", "info"},
	{"nas_linux", "TCP", 445, "SMB (ファイル共有)", "Samba ファイル共有", "info"},
	{"nas_linux", "TCP", 1194, "OpenVPN", "OpenVPN サーバー", "danger"},
	{"nas_linux", "TCP", 5000, "Synology DSM / UPnP", "Synology DSM Web 管理画面", "info"},
	{"nas_linux", "TCP", 5001, "Synology DSM (HTTPS)", "Synology DSM HTTPS 管理画面", "info"},
	{"nas_linux", "TCP", 5555, "SoftEther VPN", "SoftEther VPN サーバー", "danger"},
	{"nas_linux", "TCP", 5900, "VNC", "VNC リモートデスクトップ", "warning"},
	{"nas_linux", "TCP", 8080, "HTTP-Alt", "Web アプリケーションポート", "info"},
	{"nas_linux", "TCP", 8443, "HTTPS-Alt", "HTTPS アプリケーションポート", "info"},

	// media_iot
	{"media_iot", "TCP", 80, "HTTP", "IoT 機器 Web 管理画面", "info"},
	{"media_iot", "TCP", 443, "HTTPS", "IoT 機器 HTTPS サービス", "info"},
	{"media_iot", "TCP", 554, "RTSP (カメラ)", "ネットワークカメラ RTSP 配信", "info"},
	{"media_iot", "TCP", 8008, "Google Cast", "Google Cast 待受ポート", "info"},

	// generic
	{"generic", "TCP", 22, "SSH", "SSH サービス", "info"},
	{"generic", "TCP", 80, "HTTP", "HTTP Web サービス", "info"},
	{"generic", "TCP", 443, "HTTPS", "HTTPS サービス", "info"},
	{"generic", "TCP", 445, "SMB (ファイル共有)", "SMB ファイル共有", "info"},
	{"generic", "TCP", 1194, "OpenVPN", "OpenVPN 待受", "danger"},
	{"generic", "TCP", 1723, "PPTP VPN", "PPTP VPN 待受", "danger"},
	{"generic", "TCP", 3389, "RDP (リモートデスクトップ)", "リモートデスクトップ", "warning"},
	{"generic", "TCP", 5555, "SoftEther VPN", "SoftEther VPN 待受", "danger"},
	{"generic", "TCP", 5900, "VNC", "VNC 画面共有", "warning"},
	{"generic", "TCP", 5938, "TeamViewer", "遠隔操作ソフトウェア (緊急監視)", "danger"},
	{"generic", "TCP", 7070, "AnyDesk", "遠隔操作ソフトウェア (緊急監視)", "danger"},
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
		INSERT INTO custom_profile_ports (profile_id, protocol, port, protocol_name, description, severity, is_enabled, is_builtin)
		VALUES (?, ?, ?, ?, ?, ?, 1, 1)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, p := range BuiltinDefaultPorts {
		sev := p.Severity
		if sev == "" {
			sev = "info"
		}
		if _, err := stmt.Exec(p.ProfileID, p.Protocol, p.Port, p.ProtocolName, p.Description, sev); err != nil {
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
		INSERT INTO custom_profile_ports (profile_id, protocol, port, protocol_name, description, severity, is_enabled, is_builtin)
		VALUES (?, ?, ?, ?, ?, ?, 1, 1)
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, p := range BuiltinDefaultPorts {
		sev := p.Severity
		if sev == "" {
			sev = "info"
		}
		if _, err := stmt.Exec(p.ProfileID, p.Protocol, p.Port, p.ProtocolName, p.Description, sev); err != nil {
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
			SELECT id, profile_id, protocol, port, protocol_name, description, severity, is_enabled, is_builtin, created_at, updated_at
			FROM custom_profile_ports
			WHERE profile_id = ?
			ORDER BY port ASC, protocol ASC
		`
		args = append(args, profileID)
	} else {
		query = `
			SELECT id, profile_id, protocol, port, protocol_name, description, severity, is_enabled, is_builtin, created_at, updated_at
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
		var sev sqlNullStringCustom
		if err := rows.Scan(
			&p.ID,
			&p.ProfileID,
			&p.Protocol,
			&p.Port,
			&p.ProtocolName,
			&desc,
			&sev,
			&p.IsEnabled,
			&p.IsBuiltin,
			&p.CreatedAt,
			&p.UpdatedAt,
		); err != nil {
			return nil, fmt.Errorf("failed to scan custom port: %w", err)
		}
		p.Description = desc.String
		if sev.Valid && sev.String != "" {
			p.Severity = sev.String
		} else {
			p.Severity = "info"
		}
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
		SELECT id, profile_id, protocol, port, protocol_name, description, severity, is_enabled, is_builtin, created_at, updated_at
		FROM custom_profile_ports
		WHERE id = ?
	`
	var p CustomPort
	var desc sqlNullStringCustom
	var sev sqlNullStringCustom
	err := db.QueryRow(query, id).Scan(
		&p.ID,
		&p.ProfileID,
		&p.Protocol,
		&p.Port,
		&p.ProtocolName,
		&desc,
		&sev,
		&p.IsEnabled,
		&p.IsBuiltin,
		&p.CreatedAt,
		&p.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("custom port not found: %w", err)
	}
	p.Description = desc.String
	if sev.Valid && sev.String != "" {
		p.Severity = sev.String
	} else {
		p.Severity = "info"
	}
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
	p.Severity = strings.ToLower(strings.TrimSpace(p.Severity))
	if p.Severity != "warning" && p.Severity != "danger" {
		p.Severity = "info"
	}

	query := `
		INSERT INTO custom_profile_ports (profile_id, protocol, port, protocol_name, description, severity, is_enabled, is_builtin, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
	`
	res, err := db.Exec(query, p.ProfileID, p.Protocol, p.Port, p.ProtocolName, p.Description, p.Severity, p.IsEnabled, p.IsBuiltin)
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
func (db *DB) UpdateCustomPort(id int64, profileID, protocol string, port int, name, description, severity string, isEnabled bool) error {
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
	severity = strings.ToLower(strings.TrimSpace(severity))
	if severity != "warning" && severity != "danger" {
		severity = "info"
	}

	query := `
		UPDATE custom_profile_ports
		SET profile_id = ?, protocol = ?, port = ?, protocol_name = ?, description = ?, severity = ?, is_enabled = ?, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`
	res, err := db.Exec(query, profileID, protocol, port, name, description, severity, isEnabled, id)
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
	header := []string{"TargetOS", "Protocol", "Port", "ProtocolName", "Description", "Severity", "Enabled"}
	if err := w.Write(header); err != nil {
		return "", err
	}

	for _, p := range ports {
		sev := p.Severity
		if sev == "" {
			sev = "info"
		}
		row := []string{
			p.ProfileID,
			p.Protocol,
			strconv.Itoa(p.Port),
			p.ProtocolName,
			p.Description,
			sev,
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
	targetOSIdx, protoIdx, portIdx, nameIdx, descIdx, severityIdx, enabledIdx := -1, -1, -1, -1, -1, -1, -1

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
		case "severity", "level", "priority", "risk":
			severityIdx = i
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
		INSERT INTO custom_profile_ports (profile_id, protocol, port, protocol_name, description, severity, is_enabled, is_builtin, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, 0, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
		ON CONFLICT(profile_id, protocol, port) DO UPDATE SET
			protocol_name = excluded.protocol_name,
			description = excluded.description,
			severity = excluded.severity,
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

		severity := "info"
		if severityIdx >= 0 && severityIdx < len(row) {
			val := strings.ToLower(strings.TrimSpace(row[severityIdx]))
			if val == "danger" || val == "warning" || val == "info" {
				severity = val
			}
		}

		enabled := true
		if enabledIdx >= 0 && enabledIdx < len(row) {
			val := strings.ToLower(strings.TrimSpace(row[enabledIdx]))
			if val == "false" || val == "0" || val == "no" || val == "off" {
				enabled = false
			}
		}

		if _, err := upsertStmt.Exec(profileID, protocol, port, name, desc, severity, enabled); err != nil {
			return 0, fmt.Errorf("failed to import row %d: %w", lineNum+2, err)
		}
		count++
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}

	return count, nil
}

// GetPortSeverityMap returns a mapping of port number -> severity ("danger", "warning", "info")
// Aggregates across profiles with priority: danger > warning > info.
func (db *DB) GetPortSeverityMap() map[int]string {
	res := make(map[int]string)

	// Built-in defaults first
	for _, p := range BuiltinDefaultPorts {
		sev := p.Severity
		if sev == "" {
			sev = "info"
		}
		curr := res[p.Port]
		if curr == "danger" {
			continue
		}
		if curr == "warning" && sev != "danger" {
			continue
		}
		res[p.Port] = sev
	}

	// Override/merge from DB custom_profile_ports
	rows, err := db.Query("SELECT port, severity FROM custom_profile_ports WHERE is_enabled = 1")
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var port int
			var sev string
			if err := rows.Scan(&port, &sev); err == nil {
				sev = strings.ToLower(strings.TrimSpace(sev))
				if sev == "" {
					sev = "info"
				}
				curr := res[port]
				if curr == "danger" {
					continue
				}
				if curr == "warning" && sev != "danger" {
					continue
				}
				res[port] = sev
			}
		}
	}

	return res
}
