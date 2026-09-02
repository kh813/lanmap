package db

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// PortInfo represents a detected open port and service name
type PortInfo struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
}

// Host represents a discovered or monitored network host
type Host struct {
	IP                string     `json:"ip"`
	SegmentID         *int64     `json:"segment_id"`
	MACAddress        string     `json:"mac_address"`
	Hostname          string     `json:"hostname"`
	VendorModel       string     `json:"vendor_model"`
	DisplayName       string     `json:"display_name"`
	OSVendor          string     `json:"os_vendor"`
	Status            string     `json:"status"`
	PingRTTMs         *float64   `json:"ping_rtt_ms"`
	PingJitterMs      *float64   `json:"ping_jitter_ms"`
	UptimePct         float64    `json:"uptime_pct"`
	OpenPorts         string     `json:"open_ports"`
	HTTPTitle         string     `json:"http_title"`
	UPnPName          string     `json:"upnp_name"`
	UPnPModel         string     `json:"upnp_model"`
	UPnPSerial        string     `json:"upnp_serial"`
	TLSSubject        string     `json:"tls_subject"`
	TLSExpiry         *time.Time `json:"tls_expiry"`
	MDNSModel         string     `json:"mdns_model"`
	BroadcastCount1m  int        `json:"broadcast_count_1m"`
	IsStorming        bool       `json:"is_storming"`
	IsApproved        bool       `json:"is_approved"`
	IsProtected       bool       `json:"is_protected"`
	IsStaticIP        bool       `json:"is_static_ip"`
	IsMonitored       bool       `json:"is_monitored"`
	IsPaused          bool       `json:"is_paused"`
	HasConflict       bool       `json:"has_conflict"`
	KumaName          string     `json:"kuma_name"`
	UptimeKumaID      *int64     `json:"uptime_kuma_id"`
	FirstSeen         time.Time  `json:"first_seen"`
	LastSeen          *time.Time `json:"last_seen"`
}

// IsNewHost returns true if host was first seen within the last 24 hours and is not yet approved
func (h *Host) IsNewHost() bool {
	if h.IsApproved {
		return false
	}
	return time.Since(h.FirstSeen) < 24*time.Hour
}

// HasPingRTT returns true if Ping RTT measurement exists
func (h *Host) HasPingRTT() bool {
	return h.PingRTTMs != nil && *h.PingRTTMs >= 0
}

// PingRTTFormatted returns formatted RTT string (e.g. "2.3 ms")
func (h *Host) PingRTTFormatted() string {
	if h.PingRTTMs == nil {
		return "-"
	}
	return fmt.Sprintf("%.1f ms", *h.PingRTTMs)
}

// JitterFormatted returns formatted Jitter string (e.g. "±0.5 ms")
func (h *Host) JitterFormatted() string {
	if h.PingJitterMs == nil || *h.PingJitterMs < 0 {
		return "安定"
	}
	return fmt.Sprintf("±%.1f ms", *h.PingJitterMs)
}

// PingRTTLevel returns quality level for CSS badge styling
func (h *Host) PingRTTLevel() string {
	if h.PingRTTMs == nil {
		return "none"
	}
	if *h.PingRTTMs < 15.0 {
		return "fast"
	} else if *h.PingRTTMs < 60.0 {
		return "normal"
	}
	return "slow"
}

// OpenPortsList parses comma-separated "port:service" string into slice of PortInfo
func (h *Host) OpenPortsList() []PortInfo {
	if strings.TrimSpace(h.OpenPorts) == "" {
		return nil
	}
	var list []PortInfo
	parts := strings.Split(h.OpenPorts, ",")
	for _, p := range parts {
		kv := strings.SplitN(strings.TrimSpace(p), ":", 2)
		if len(kv) >= 1 {
			portNum, err := strconv.Atoi(kv[0])
			if err == nil {
				svcName := "Unknown"
				if len(kv) == 2 {
					svcName = kv[1]
				}
				list = append(list, PortInfo{Port: portNum, Service: svcName})
			}
		}
	}
	return list
}

// HasOpenPorts returns true if any open ports were detected
func (h *Host) HasOpenPorts() bool {
	return len(h.OpenPortsList()) > 0
}

// HasTLS returns true if TLS info is available
func (h *Host) HasTLS() bool {
	return h.TLSSubject != "" || h.TLSExpiry != nil
}

// TLSExpiresSoon returns true if certificate expires within 30 days
func (h *Host) TLSExpiresSoon() bool {
	if h.TLSExpiry == nil {
		return false
	}
	return time.Until(*h.TLSExpiry) < 30*24*time.Hour
}

// DaysUntilTLSExpiry returns days remaining until certificate expiry
func (h *Host) DaysUntilTLSExpiry() int {
	if h.TLSExpiry == nil {
		return 0
	}
	days := int(time.Until(*h.TLSExpiry).Hours() / 24)
	if days < 0 {
		return 0
	}
	return days
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
			os_vendor, status, ping_rtt_ms, ping_jitter_ms, uptime_pct,
			open_ports, http_title, upnp_name, upnp_model, upnp_serial,
			tls_subject, tls_expiry, mdns_model, broadcast_count_1m, is_storming,
			is_approved, is_protected, is_static_ip,
			is_monitored, is_paused, has_conflict, kuma_name, uptime_kuma_id,
			first_seen, last_seen
		) VALUES (
			?, ?, ?, ?, ?, ?,
			?, ?, ?, ?, 100.0,
			?, ?, ?, ?, ?,
			?, ?, ?, 0, 0,
			?, 0, 0,
			0, 0, 0, '', NULL,
			?, ?
		)
		`
		_, err := db.Exec(query,
			h.IP, h.SegmentID, normMAC, h.Hostname, h.VendorModel, h.DisplayName,
			h.OSVendor, h.Status, h.PingRTTMs, h.PingJitterMs,
			h.OpenPorts, h.HTTPTitle, h.UPnPName, h.UPnPModel, h.UPnPSerial,
			h.TLSSubject, h.TLSExpiry, h.MDNSModel,
			h.IsApproved, now, now,
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

	jitter := h.PingJitterMs
	if jitter == nil {
		jitter = existing.PingJitterMs
	}

	openPorts := h.OpenPorts
	httpTitle := h.HTTPTitle
	upnpName := h.UPnPName
	if upnpName == "" && h.UPnPModel == "" {
		upnpName = existing.UPnPName
	}
	upnpModel := h.UPnPModel
	if upnpModel == "" {
		upnpModel = existing.UPnPModel
	}
	upnpSerial := h.UPnPSerial
	if upnpSerial == "" {
		upnpSerial = existing.UPnPSerial
	}
	tlsSubj := h.TLSSubject
	tlsExp := h.TLSExpiry
	if tlsSubj == "" && tlsExp == nil && existing.TLSSubject != "" {
		// Check if port 443/8443 is still open
		if strings.Contains(openPorts, "443") || strings.Contains(openPorts, "8443") {
			tlsSubj = existing.TLSSubject
			tlsExp = existing.TLSExpiry
		}
	}
	mdnsModel := h.MDNSModel
	if mdnsModel == "" {
		mdnsModel = existing.MDNSModel
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
		ping_jitter_ms = ?,
		open_ports = ?,
		http_title = ?,
		upnp_name = ?,
		upnp_model = ?,
		upnp_serial = ?,
		tls_subject = ?,
		tls_expiry = ?,
		mdns_model = ?,
		is_approved = ?,
		first_seen = ?,
		last_seen = ?
	WHERE ip = ?
	`
	_, err = db.Exec(query,
		h.SegmentID, mac, hostname, vendorModel, displayName,
		osVendor, h.Status, pingRTT, jitter, openPorts,
		httpTitle, upnpName, upnpModel, upnpSerial,
		tlsSubj, tlsExp, mdnsModel,
		isApproved, firstSeen, now, h.IP,
	)
	return false, isReplaced, err
}

// GetHost fetches a host by IP
func (db *DB) GetHost(ip string) (*Host, error) {
	query := `
	SELECT
		ip, segment_id, mac_address, hostname, vendor_model, display_name,
		os_vendor, status, ping_rtt_ms, ping_jitter_ms, uptime_pct,
		open_ports, http_title, upnp_name, upnp_model, upnp_serial,
		tls_subject, tls_expiry, mdns_model, broadcast_count_1m, is_storming,
		is_approved, is_protected, is_static_ip,
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
		os_vendor, status, ping_rtt_ms, ping_jitter_ms, uptime_pct,
		open_ports, http_title, upnp_name, upnp_model, upnp_serial,
		tls_subject, tls_expiry, mdns_model, broadcast_count_1m, is_storming,
		is_approved, is_protected, is_static_ip,
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

	query.WriteString(" ORDER BY is_storming DESC, is_approved ASC, ip ASC")

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
		query = "UPDATE hosts SET status = ?, ping_rtt_ms = NULL, ping_jitter_ms = NULL WHERE ip = ?"
		args = []interface{}{status, ip}
	}

	_, err := db.Exec(query, args...)
	return err
}

// UpdateHostBroadcastStats updates broadcast traffic stats and storm status
func (db *DB) UpdateHostBroadcastStats(ip string, count1m int, isStorming bool) error {
	query := "UPDATE hosts SET broadcast_count_1m = ?, is_storming = ? WHERE ip = ?"
	_, err := db.Exec(query, count1m, isStorming, ip)
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
		os_vendor, status, ping_rtt_ms, ping_jitter_ms, uptime_pct,
		open_ports, http_title, upnp_name, upnp_model, upnp_serial,
		tls_subject, tls_expiry, mdns_model, broadcast_count_1m, is_storming,
		is_approved, is_protected, is_static_ip,
		is_monitored, is_paused, has_conflict, kuma_name, uptime_kuma_id,
		first_seen, last_seen
	) VALUES (
		?, ?, ?, ?, ?, ?,
		?, ?, ?, ?, 100.0,
		?, ?, ?, ?, ?,
		?, ?, ?, ?, ?,
		?, ?, ?,
		?, ?, ?, ?, ?,
		?, ?
	)
	`
	_, err := db.Exec(query,
		h.IP, h.SegmentID, normMAC, h.Hostname, h.VendorModel, h.DisplayName,
		h.OSVendor, h.Status, h.PingRTTMs, h.PingJitterMs,
		h.OpenPorts, h.HTTPTitle, h.UPnPName, h.UPnPModel, h.UPnPSerial,
		h.TLSSubject, h.TLSExpiry, h.MDNSModel, h.BroadcastCount1m, h.IsStorming,
		h.IsApproved, h.IsProtected, h.IsStaticIP,
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
	var mac, host, vendor, disp, osVend, kumaName, openPorts sql.NullString
	var httpTitle, upnpName, upnpModel, upnpSerial, tlsSubj, mdnsModel sql.NullString
	var kumaID sql.NullInt64
	var lastSeen, tlsExp sql.NullTime
	var rtt, jitter, uptime sql.NullFloat64

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
		&jitter,
		&uptime,
		&openPorts,
		&httpTitle,
		&upnpName,
		&upnpModel,
		&upnpSerial,
		&tlsSubj,
		&tlsExp,
		&mdnsModel,
		&h.BroadcastCount1m,
		&h.IsStorming,
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
	h.OpenPorts = openPorts.String
	h.HTTPTitle = httpTitle.String
	h.UPnPName = upnpName.String
	h.UPnPModel = upnpModel.String
	h.UPnPSerial = upnpSerial.String
	h.TLSSubject = tlsSubj.String
	h.MDNSModel = mdnsModel.String

	if rtt.Valid {
		val := rtt.Float64
		h.PingRTTMs = &val
	}
	if jitter.Valid {
		val := jitter.Float64
		h.PingJitterMs = &val
	}
	if uptime.Valid {
		h.UptimePct = uptime.Float64
	} else {
		h.UptimePct = 100.0
	}

	if tlsExp.Valid {
		h.TLSExpiry = &tlsExp.Time
	}
	if kumaID.Valid {
		h.UptimeKumaID = &kumaID.Int64
	}
	if lastSeen.Valid {
		h.LastSeen = &lastSeen.Time
	}

	return &h, nil
}
