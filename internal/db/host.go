package db

import (
	"database/sql"
	"strings"
	"time"
)

// Host represents a discovered or monitored network host
type Host struct {
	IP           string     `json:"ip"`
	SegmentID    *int64     `json:"segment_id"`
	MACAddress   string     `json:"mac_address"`
	Hostname     string     `json:"hostname"`
	VendorModel  string     `json:"vendor_model"`
	DisplayName  string     `json:"display_name"`
	OSVendor     string     `json:"os_vendor"`
	Status       string     `json:"status"`
	PingRTTMs    *float64   `json:"ping_rtt_ms"`
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

// IsNewHost returns true if host was first seen within the last 24 hours and is not yet approved
func (h *Host) IsNewHost() bool {
	if h.IsApproved {
		return false
	}
	return time.Since(h.FirstSeen) < 24*time.Hour
}

// UpsertHostOnScan inserts a newly scanned host or updates an existing host
func (db *DB) UpsertHostOnScan(h *Host) (isNew bool, isReplaced bool, err error) {
	existing, err := db.GetHost(h.IP)
	if err != nil {
		return false, false, err
	}

	now := time.Now()
	normMAC := strings.ToLower(strings.TrimSpace(h.MACAddress))

	if existing == nil {
		query := `
		INSERT INTO hosts (
			ip, segment_id, mac_address, hostname, vendor_model, display_name,
			os_vendor, status, ping_rtt_ms, is_approved, is_protected, is_static_ip,
			is_monitored, is_paused, has_conflict, kuma_name, uptime_kuma_id,
			first_seen, last_seen
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, 0, 0, 0, 0, '', NULL, ?, ?)
		`
		_, err := db.Exec(query,
			h.IP, h.SegmentID, normMAC, h.Hostname, h.VendorModel, h.DisplayName,
			h.OSVendor, h.Status, h.PingRTTMs, h.IsApproved, now, now,
		)
		return true, false, err
	}

	isReplaced = false
	if existing.MACAddress != "" && normMAC != "" && !strings.EqualFold(existing.MACAddress, normMAC) {
		isReplaced = true
	}

	isApproved := existing.IsApproved
	firstSeen := existing.FirstSeen
	if isReplaced {
		isApproved = false
		firstSeen = now
	} else if h.IsApproved {
		isApproved = true
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
	displayName := existing.DisplayName
	if displayName == "" && h.DisplayName != "" {
		displayName = h.DisplayName
	}

	mac := existing.MACAddress
	if normMAC != "" {
		mac = normMAC
	}

	pingRTT := h.PingRTTMs
	if pingRTT == nil {
		pingRTT = existing.PingRTTMs
	}

	query := `
	UPDATE hosts SET
		segment_id = COALESCE(?, segment_id),
		mac_address = ?,
		hostname = ?,
		vendor_model = ?,
		display_name = ?,
		os_vendor = ?,
		status = ?,
		ping_rtt_ms = ?,
		is_approved = ?,
		first_seen = ?,
		last_seen = ?
	WHERE ip = ?
	`
	_, err = db.Exec(query,
		h.SegmentID, mac, hostname, vendorModel, displayName,
		osVendor, h.Status, pingRTT, isApproved, firstSeen, now, h.IP,
	)
	return false, isReplaced, err
}

// GetHost fetches a host by IP
func (db *DB) GetHost(ip string) (*Host, error) {
	query := `
	SELECT
		ip, segment_id, mac_address, hostname, vendor_model, display_name,
		os_vendor, status, ping_rtt_ms, is_approved, is_protected, is_static_ip,
		is_monitored, is_paused, has_conflict, kuma_name, uptime_kuma_id,
		first_seen, last_seen
	FROM hosts
	WHERE ip = ?
	`
	row := db.QueryRow(query, ip)
	return scanHost(row)
}

// ListHosts lists hosts, optionally filtered by segment and online status
func (db *DB) ListHosts(segmentID *int64, onlineOnly bool) ([]*Host, error) {
	var query strings.Builder
	var args []interface{}

	query.WriteString(`
	SELECT
		ip, segment_id, mac_address, hostname, vendor_model, display_name,
		os_vendor, status, ping_rtt_ms, is_approved, is_protected, is_static_ip,
		is_monitored, is_paused, has_conflict, kuma_name, uptime_kuma_id,
		first_seen, last_seen
	FROM hosts
	WHERE 1=1
	`)

	if segmentID != nil {
		query.WriteString(" AND segment_id = ?")
		args = append(args, *segmentID)
	}

	if onlineOnly {
		query.WriteString(" AND status = 'up'")
	}

	query.WriteString(" ORDER BY is_approved ASC, ip ASC")

	rows, err := db.Query(query.String(), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []*Host
	for rows.Next() {
		h, err := scanHost(rows)
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, h)
	}

	return hosts, rows.Err()
}

// UpdateHostStatus updates the host status and last_seen if up
func (db *DB) UpdateHostStatus(ip string, status string) error {
	now := time.Now()
	var query string
	var args []interface{}

	if status == "up" {
		query = "UPDATE hosts SET status = ?, last_seen = ? WHERE ip = ?"
		args = []interface{}{status, now, ip}
	} else {
		query = "UPDATE hosts SET status = ?, ping_rtt_ms = NULL WHERE ip = ?"
		args = []interface{}{status, ip}
	}

	_, err := db.Exec(query, args...)
	return err
}

// UpdateHostKumaStatus updates Uptime Kuma monitoring link and status
func (db *DB) UpdateHostKumaStatus(ip string, kumaID *int64, isMonitored, isPaused, hasConflict bool, kumaName string) error {
	query := `
	UPDATE hosts SET
		uptime_kuma_id = ?,
		is_monitored = ?,
		is_paused = ?,
		has_conflict = ?,
		kuma_name = ?
	WHERE ip = ?
	`
	_, err := db.Exec(query, kumaID, isMonitored, isPaused, hasConflict, kumaName, ip)
	return err
}

// ToggleApproval toggles the approval status of a host
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

// ToggleProtection toggles the protection flag of a host
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
	query := `
	UPDATE hosts SET
		display_name = ?,
		vendor_model = CASE WHEN ? != '' THEN ? ELSE vendor_model END,
		is_static_ip = ?
	WHERE ip = ?
	`
	_, err := db.Exec(query, displayName, vendorModel, vendorModel, isStaticIP, ip)
	return err
}

// CreateManualHost creates a manually registered host
func (db *DB) CreateManualHost(h *Host) error {
	now := time.Now()
	normMAC := strings.ToLower(strings.TrimSpace(h.MACAddress))
	query := `
	INSERT INTO hosts (
		ip, segment_id, mac_address, hostname, vendor_model, display_name,
		os_vendor, status, ping_rtt_ms, is_approved, is_protected, is_static_ip,
		is_monitored, is_paused, has_conflict, kuma_name, uptime_kuma_id,
		first_seen, last_seen
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`
	_, err := db.Exec(query,
		h.IP, h.SegmentID, normMAC, h.Hostname, h.VendorModel, h.DisplayName,
		h.OSVendor, h.Status, h.PingRTTMs, h.IsApproved, h.IsProtected, h.IsStaticIP,
		h.IsMonitored, h.IsPaused, h.HasConflict, h.KumaName, h.UptimeKumaID,
		now, now,
	)
	return err
}

// DeleteHost deletes a host by IP
func (db *DB) DeleteHost(ip string) error {
	_, err := db.Exec("DELETE FROM hosts WHERE ip = ?", ip)
	return err
}

type scannable interface {
	Scan(dest ...interface{}) error
}

func scanHost(s scannable) (*Host, error) {
	var h Host
	var segID sql.NullInt64
	var mac, host, vendor, disp, osVend, kumaName sql.NullString
	var kumaID sql.NullInt64
	var lastSeen sql.NullTime
	var rtt sql.NullFloat64

	err := s.Scan(
		&h.IP,
		&segID,
		&mac,
		&host,
		&vendor,
		&disp,
		&osVend,
		&h.Status,
		&rtt,
		&h.IsApproved,
		&h.IsProtected,
		&h.IsStaticIP,
		&h.IsMonitored,
		&h.IsPaused,
		&h.HasConflict,
		&kumaName,
		&kumaID,
		&h.FirstSeen,
		&lastSeen,
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
	h.MACAddress = mac.String
	h.Hostname = host.String
	h.VendorModel = vendor.String
	h.DisplayName = disp.String
	h.OSVendor = osVend.String
	h.KumaName = kumaName.String

	if rtt.Valid {
		val := rtt.Float64
		h.PingRTTMs = &val
	}

	if kumaID.Valid {
		h.UptimeKumaID = &kumaID.Int64
	}
	if lastSeen.Valid {
		h.LastSeen = &lastSeen.Time
	}

	return &h, nil
}
