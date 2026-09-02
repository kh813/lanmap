package db

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Host represents a network host
type Host struct {
	IP           string     `json:"ip"`
	SegmentID    *int64     `json:"segment_id"`
	SegmentName  string     `json:"segment_name,omitempty"`
	MACAddress   string     `json:"mac_address"`
	Hostname     string     `json:"hostname"`
	VendorModel  string     `json:"vendor_model"`
	DisplayName  string     `json:"display_name"`
	OSVendor     string     `json:"os_vendor"`
	Status       string     `json:"status"`
	IsApproved   bool       `json:"is_approved"`
	IsProtected  bool       `json:"is_protected"`
	IsStaticIP   bool       `json:"is_static_ip"`
	IsMonitored  bool       `json:"is_monitored"`
	IsPaused     bool       `json:"is_paused"`
	HasConflict  bool       `json:"has_conflict"`
	KumaName     string     `json:"kuma_name"`
	UptimeKumaID *int64     `json:"uptime_kuma_id"`
	FirstSeen    time.Time  `json:"first_seen"`
	LastSeen     *time.Time `json:"last_seen"`
}

// IsNewHost indicates if host was first seen within the last 24 hours and is not yet approved
func (h *Host) IsNewHost() bool {
	if h.IsApproved {
		return false
	}
	return time.Since(h.FirstSeen) < 24*time.Hour
}

// UpsertHostOnScan handles scan host insertion/updating with MAC address reuse detection (4.2.1)
func (db *DB) UpsertHostOnScan(h *Host) (isNew bool, isReplaced bool, err error) {
	existing, err := db.GetHost(h.IP)
	if err != nil {
		return false, false, err
	}

	now := time.Now().UTC()

	if existing == nil {
		// New host detected
		query := `
		INSERT INTO hosts (
			ip, segment_id, mac_address, hostname, vendor_model, display_name,
			os_vendor, status, is_approved, is_protected, is_static_ip,
			is_monitored, is_paused, has_conflict, kuma_name, uptime_kuma_id,
			first_seen, last_seen
		) VALUES (?, ?, ?, ?, ?, ?, ?, 'up', 0, 0, 0, 0, 0, 0, '', NULL, ?, ?)
		`
		_, err = db.Exec(query,
			h.IP, h.SegmentID, h.MACAddress, h.Hostname, h.VendorModel,
			h.DisplayName, h.OSVendor, now, now,
		)
		if err != nil {
			return false, false, fmt.Errorf("failed to insert new host: %w", err)
		}
		return true, false, nil
	}

	// Host exists for this IP. Check MAC address mismatch
	if existing.MACAddress != "" && h.MACAddress != "" && !strings.EqualFold(existing.MACAddress, h.MACAddress) {
		// IP has been reassigned to a different physical device!
		// Reset is_approved to 0, update first_seen and replace MAC & details
		query := `
		UPDATE hosts SET
			segment_id = ?,
			mac_address = ?,
			hostname = ?,
			vendor_model = ?,
			display_name = ?,
			os_vendor = ?,
			status = 'up',
			is_approved = 0,
			first_seen = ?,
			last_seen = ?
		WHERE ip = ?
		`
		dispName := existing.DisplayName
		if h.DisplayName != "" {
			dispName = h.DisplayName
		}
		_, err = db.Exec(query,
			h.SegmentID, h.MACAddress, h.Hostname, h.VendorModel,
			dispName, h.OSVendor, now, now, h.IP,
		)
		if err != nil {
			return false, false, fmt.Errorf("failed to replace host on MAC change: %w", err)
		}
		return false, true, nil
	}

	// Same host - update status and scan data without losing approval/protection
	mac := existing.MACAddress
	if mac == "" && h.MACAddress != "" {
		mac = h.MACAddress
	}
	hostname := existing.Hostname
	if h.Hostname != "" {
		hostname = h.Hostname
	}
	vendorModel := existing.VendorModel
	if h.VendorModel != "" {
		vendorModel = h.VendorModel
	}
	osVendor := existing.OSVendor
	if h.OSVendor != "" {
		osVendor = h.OSVendor
	}
	segID := existing.SegmentID
	if h.SegmentID != nil {
		segID = h.SegmentID
	}

	query := `
	UPDATE hosts SET
		segment_id = ?,
		mac_address = ?,
		hostname = ?,
		vendor_model = ?,
		os_vendor = ?,
		status = 'up',
		last_seen = ?
	WHERE ip = ?
	`
	_, err = db.Exec(query, segID, mac, hostname, vendorModel, osVendor, now, h.IP)
	if err != nil {
		return false, false, fmt.Errorf("failed to update existing host: %w", err)
	}

	return false, false, nil
}

// CreateManualHost creates a host manually
func (db *DB) CreateManualHost(h *Host) error {
	now := time.Now().UTC()
	query := `
	INSERT INTO hosts (
		ip, segment_id, mac_address, hostname, vendor_model, display_name,
		os_vendor, status, is_approved, is_protected, is_static_ip,
		is_monitored, is_paused, has_conflict, kuma_name, uptime_kuma_id,
		first_seen, last_seen
	) VALUES (?, ?, ?, ?, ?, ?, ?, 'up', ?, ?, ?, 0, 0, 0, '', NULL, ?, ?)
	`
	_, err := db.Exec(query,
		h.IP, h.SegmentID, h.MACAddress, h.Hostname, h.VendorModel,
		h.DisplayName, h.OSVendor, h.IsApproved, h.IsProtected, h.IsStaticIP,
		now, now,
	)
	return err
}

// GetHost retrieves a single host by IP
func (db *DB) GetHost(ip string) (*Host, error) {
	query := `
	SELECT 
		h.ip, h.segment_id, s.name, h.mac_address, h.hostname, h.vendor_model,
		h.display_name, h.os_vendor, h.status, h.is_approved, h.is_protected,
		h.is_static_ip, h.is_monitored, h.is_paused, h.has_conflict,
		h.kuma_name, h.uptime_kuma_id, h.first_seen, h.last_seen
	FROM hosts h
	LEFT JOIN segments s ON h.segment_id = s.id
	WHERE h.ip = ?
	`
	row := db.QueryRow(query, ip)

	var h Host
	var segID sql.NullInt64
	var segName sql.NullString
	var mac, hostname, vendor, dispName, osVendor, status, kumaName sql.NullString
	var kumaID sql.NullInt64
	var lastSeen sql.NullTime

	err := row.Scan(
		&h.IP, &segID, &segName, &mac, &hostname, &vendor,
		&dispName, &osVendor, &status, &h.IsApproved, &h.IsProtected,
		&h.IsStaticIP, &h.IsMonitored, &h.IsPaused, &h.HasConflict,
		&kumaName, &kumaID, &h.FirstSeen, &lastSeen,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return nil, nil
		}
		return nil, err
	}

	if segID.Valid {
		h.SegmentID = &segID.Int64
	}
	h.SegmentName = segName.String
	h.MACAddress = mac.String
	h.Hostname = hostname.String
	h.VendorModel = vendor.String
	h.DisplayName = dispName.String
	h.OSVendor = osVendor.String
	h.Status = status.String
	h.KumaName = kumaName.String
	if kumaID.Valid {
		h.UptimeKumaID = &kumaID.Int64
	}
	if lastSeen.Valid {
		h.LastSeen = &lastSeen.Time
	}

	return &h, nil
}

// ListHosts lists hosts filtered by segmentID and status
func (db *DB) ListHosts(segmentID *int64, onlineOnly bool) ([]*Host, error) {
	query := `
	SELECT 
		h.ip, h.segment_id, s.name, h.mac_address, h.hostname, h.vendor_model,
		h.display_name, h.os_vendor, h.status, h.is_approved, h.is_protected,
		h.is_static_ip, h.is_monitored, h.is_paused, h.has_conflict,
		h.kuma_name, h.uptime_kuma_id, h.first_seen, h.last_seen
	FROM hosts h
	LEFT JOIN segments s ON h.segment_id = s.id
	WHERE 1=1
	`
	var args []interface{}

	if segmentID != nil {
		query += " AND (h.segment_id = ? OR (? IS NULL AND h.segment_id IS NULL))"
		args = append(args, *segmentID, *segmentID)
	}
	if onlineOnly {
		query += " AND h.status = 'up'"
	}

	query += " ORDER BY h.ip ASC"

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var list []*Host
	for rows.Next() {
		var h Host
		var segID sql.NullInt64
		var segName sql.NullString
		var mac, hostname, vendor, dispName, osVendor, status, kumaName sql.NullString
		var kumaID sql.NullInt64
		var lastSeen sql.NullTime

		err := rows.Scan(
			&h.IP, &segID, &segName, &mac, &hostname, &vendor,
			&dispName, &osVendor, &status, &h.IsApproved, &h.IsProtected,
			&h.IsStaticIP, &h.IsMonitored, &h.IsPaused, &h.HasConflict,
			&kumaName, &kumaID, &h.FirstSeen, &lastSeen,
		)
		if err != nil {
			return nil, err
		}

		if segID.Valid {
			h.SegmentID = &segID.Int64
		}
		h.SegmentName = segName.String
		h.MACAddress = mac.String
		h.Hostname = hostname.String
		h.VendorModel = vendor.String
		h.DisplayName = dispName.String
		h.OSVendor = osVendor.String
		h.Status = status.String
		h.KumaName = kumaName.String
		if kumaID.Valid {
			h.UptimeKumaID = &kumaID.Int64
		}
		if lastSeen.Valid {
			h.LastSeen = &lastSeen.Time
		}

		list = append(list, &h)
	}

	return list, rows.Err()
}

// ToggleApproval toggles the is_approved status of a host
func (db *DB) ToggleApproval(ip string) (bool, error) {
	var current bool
	err := db.QueryRow("SELECT is_approved FROM hosts WHERE ip = ?", ip).Scan(&current)
	if err != nil {
		return false, err
	}
	newVal := !current
	_, err = db.Exec("UPDATE hosts SET is_approved = ? WHERE ip = ?", newVal, ip)
	return newVal, err
}

// ToggleProtection toggles the is_protected status of a host
func (db *DB) ToggleProtection(ip string) (bool, error) {
	var current bool
	err := db.QueryRow("SELECT is_protected FROM hosts WHERE ip = ?", ip).Scan(&current)
	if err != nil {
		return false, err
	}
	newVal := !current
	_, err = db.Exec("UPDATE hosts SET is_protected = ? WHERE ip = ?", newVal, ip)
	return newVal, err
}

// UpdateHostManual updates manually editable fields
func (db *DB) UpdateHostManual(ip, displayName, vendorModel string, isStaticIP bool) error {
	_, err := db.Exec(
		"UPDATE hosts SET display_name = ?, vendor_model = ?, is_static_ip = ? WHERE ip = ?",
		displayName, vendorModel, isStaticIP, ip,
	)
	return err
}

// UpdateHostKumaStatus updates Uptime Kuma sync fields
func (db *DB) UpdateHostKumaStatus(ip string, kumaID *int64, isMonitored, isPaused, hasConflict bool, kumaName string) error {
	_, err := db.Exec(
		"UPDATE hosts SET uptime_kuma_id = ?, is_monitored = ?, is_paused = ?, has_conflict = ?, kuma_name = ? WHERE ip = ?",
		kumaID, isMonitored, isPaused, hasConflict, kumaName, ip,
	)
	return err
}

// UpdateHostStatus updates host status (up / down)
func (db *DB) UpdateHostStatus(ip, status string) error {
	var err error
	if status == "up" {
		_, err = db.Exec("UPDATE hosts SET status = 'up', last_seen = ? WHERE ip = ?", time.Now().UTC(), ip)
	} else {
		_, err = db.Exec("UPDATE hosts SET status = 'down' WHERE ip = ?", ip)
	}
	return err
}

// DeleteHost deletes a host by IP
func (db *DB) DeleteHost(ip string) error {
	_, err := db.Exec("DELETE FROM hosts WHERE ip = ?", ip)
	return err
}
