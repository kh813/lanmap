package db

import (
	"database/sql"
	"fmt"
	"html/template"
	"net"
	"sort"
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
	IP                string        `json:"ip"`
	SegmentID         *int64        `json:"segment_id"`
	MACAddress        string        `json:"mac_address"`
	Hostname          string        `json:"hostname"`
	VendorModel       string        `json:"vendor_model"`
	DisplayName       string        `json:"display_name"`
	OSVendor          string        `json:"os_vendor"`
	Status            string        `json:"status"`
	PingRTTMs         *float64      `json:"ping_rtt_ms"`
	PingJitterMs      *float64      `json:"ping_jitter_ms"`
	UptimePct         float64       `json:"uptime_pct"`
	OpenPorts         string        `json:"open_ports"`
	HTTPTitle         string        `json:"http_title"`
	UPnPName          string        `json:"upnp_name"`
	UPnPModel         string        `json:"upnp_model"`
	UPnPSerial        string        `json:"upnp_serial"`
	TLSSubject        string        `json:"tls_subject"`
	TLSExpiry         *time.Time    `json:"tls_expiry"`
	MDNSModel         string        `json:"mdns_model"`
	BroadcastCount1m  int           `json:"broadcast_count_1m"`
	IsStorming        bool          `json:"is_storming"`
	IsApproved        bool          `json:"is_approved"`
	IsProtected       bool          `json:"is_protected"`
	IsStaticIP        bool          `json:"is_static_ip"`
	IsDHCP            bool          `json:"is_dhcp"`
	IsMonitored       bool          `json:"is_monitored"`
	IsPaused          bool          `json:"is_paused"`
	HasConflict       bool          `json:"has_conflict"`
	KumaName          string        `json:"kuma_name"`
	UptimeKumaID      *int64        `json:"uptime_kuma_id"`
	FirstSeen         time.Time     `json:"first_seen"`
	LastSeen          *time.Time    `json:"last_seen"`
	PingChartSVG      template.HTML `json:"-"`
	UptimeBlocksSVG   template.HTML `json:"-"`
	PingStats7d       string        `json:"-"`
}

// IPID returns sanitized IP string for HTML element IDs (e.g. "192-168-1-1")
func (h *Host) IPID() string {
	return strings.ReplaceAll(strings.ReplaceAll(h.IP, ".", "-"), ":", "-")
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

// IsRandomizedMAC returns true if the MAC address has the Locally Administered Address (LAA) bit set
func (h *Host) IsRandomizedMAC() bool {
	mac := strings.ToLower(strings.TrimSpace(h.MACAddress))
	if len(mac) < 2 {
		return false
	}
	// Check second hex digit of first byte (2, 6, a, e indicate randomized/LAA MAC)
	secondChar := mac[1]
	return secondChar == '2' || secondChar == '6' || secondChar == 'a' || secondChar == 'e'
}

// ConnectionType returns "wifi", "ethernet", or "unknown"
func (h *Host) ConnectionType() string {
	combined := strings.ToLower(h.Hostname + " " + h.MDNSModel + " " + h.VendorModel + " " + h.UPnPName + " " + h.DisplayName)

	// 1. Definite mobile / wireless-only device classes
	if strings.Contains(combined, "iphone") ||
		strings.Contains(combined, "ipad") ||
		strings.Contains(combined, "watch") ||
		strings.Contains(combined, "galaxy") ||
		strings.Contains(combined, "pixel") ||
		strings.Contains(combined, "android") ||
		strings.Contains(combined, "google home") ||
		strings.Contains(combined, "nest") ||
		strings.Contains(combined, "echo") ||
		strings.Contains(combined, "homepod") ||
		strings.Contains(combined, "cast") ||
		strings.Contains(combined, "espressif") ||
		strings.Contains(combined, "tuya") ||
		strings.Contains(combined, "shelly") ||
		strings.Contains(combined, "switch") ||
		strings.Contains(combined, "airplay") {
		return "wifi"
	}

	// 2. Private / Randomized MAC is almost exclusively used on Wi-Fi interfaces
	if h.IsRandomizedMAC() {
		return "wifi"
	}

	// 3. Known wired infrastructure (Routers, Gateways, Managed Switches, NAS, Hypervisors, Network APs)
	if strings.Contains(combined, "openwrt") ||
		strings.Contains(combined, "luci") ||
		strings.Contains(combined, "synology") ||
		strings.Contains(combined, "qnap") ||
		strings.Contains(combined, "truenas") ||
		strings.Contains(combined, "proxmox") ||
		strings.Contains(combined, "esxi") ||
		strings.Contains(combined, "netgear") ||
		strings.Contains(combined, "cisco") ||
		strings.Contains(combined, "ubiquiti") ||
		strings.Contains(combined, "unifi") ||
		strings.Contains(combined, "yamaha") ||
		strings.Contains(combined, "fortinet") ||
		strings.Contains(combined, "mikrotik") ||
		strings.Contains(combined, "allied telesis") ||
		strings.Contains(combined, "juniper") ||
		strings.Contains(combined, "aruba") ||
		strings.Contains(combined, "router") ||
		strings.Contains(combined, "access point") ||
		strings.Contains(combined, "server") {
		return "ethernet"
	}

	// 4. Ping latency & jitter statistical signature
	if h.PingRTTMs != nil && *h.PingRTTMs >= 0 {
		if *h.PingRTTMs < 0.8 && (h.PingJitterMs == nil || *h.PingJitterMs < 0.2) {
			return "ethernet"
		}
		if *h.PingRTTMs >= 1.5 || (h.PingJitterMs != nil && *h.PingJitterMs >= 0.4) {
			return "wifi"
		}
	}

	return "unknown"
}

// ConnectionLabel returns user-friendly label (e.g. "📶 Wi-Fi", "🔌 有線LAN")
func (h *Host) ConnectionLabel() string {
	switch h.ConnectionType() {
	case "wifi":
		return "📶 Wi-Fi"
	case "ethernet":
		return "🔌 有線LAN"
	default:
		return "❓ 不明"
	}
}

// ConnectionBadgeClass returns Tailwind badge styling class
func (h *Host) ConnectionBadgeClass() string {
	switch h.ConnectionType() {
	case "wifi":
		return "bg-sky-50 text-sky-700 dark:bg-sky-950/60 dark:text-sky-300 border-sky-200 dark:border-sky-800/60"
	case "ethernet":
		return "bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300 border-slate-200 dark:border-slate-700"
	default:
		return "bg-slate-50 text-slate-500 dark:bg-slate-900 dark:text-slate-400 border-slate-200 dark:border-slate-800"
	}
}

// ConnectionReason returns human-readable explanation of why this connection type was determined
func (h *Host) ConnectionReason() string {
	combined := strings.ToLower(h.Hostname + " " + h.MDNSModel + " " + h.VendorModel + " " + h.UPnPName + " " + h.DisplayName)
	if strings.Contains(combined, "iphone") || strings.Contains(combined, "ipad") || strings.Contains(combined, "watch") || strings.Contains(combined, "galaxy") {
		return "モバイル機器"
	}
	if strings.Contains(combined, "google home") || strings.Contains(combined, "cast") || strings.Contains(combined, "espressif") {
		return "スマート家電/IoT"
	}
	if h.IsRandomizedMAC() {
		return "ランダムMAC"
	}
	if strings.Contains(combined, "netgear") || strings.Contains(combined, "cisco") || strings.Contains(combined, "yamaha") || strings.Contains(combined, "ubiquiti") || strings.Contains(combined, "router") || strings.Contains(combined, "access point") {
		return "ネットワーク機器 (AP/ルーター)"
	}
	if strings.Contains(combined, "openwrt") || strings.Contains(combined, "synology") || strings.Contains(combined, "server") {
		return "固定インフラ"
	}
	if h.PingRTTMs != nil && *h.PingRTTMs < 0.8 {
		return "超低遅延 (<0.8ms)"
	}
	if h.PingRTTMs != nil && *h.PingRTTMs >= 1.5 {
		return "遅延/ジッター特性"
	}
	return "推定"
}

// SearchKeywords returns a consolidated lowercase string of all searchable attributes of the host
func (h *Host) SearchKeywords() string {
	var parts []string
	parts = append(parts, h.IP, h.Hostname, h.DisplayName, h.MACAddress, h.VendorModel, h.OSVendor, h.MDNSModel, h.HTTPTitle, h.UPnPName, h.UPnPModel, h.OpenPorts, h.Status, h.ConnectionLabel(), h.ConnectionReason())
	if h.IsApproved {
		parts = append(parts, "承認", "承認済", "approved")
	} else {
		parts = append(parts, "未承認", "unapproved", "警告")
	}
	if h.IsStaticIP {
		parts = append(parts, "固定ip", "static")
	}
	if h.IsStorming {
		parts = append(parts, "ストーム", "異常通信", "storm")
	}
	return strings.ToLower(strings.Join(parts, " "))
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
			is_approved, is_protected, is_static_ip, is_dhcp,
			is_monitored, is_paused, has_conflict, kuma_name, uptime_kuma_id,
			first_seen, last_seen
		) VALUES (
			?, ?, ?, ?, ?, ?,
			?, ?, ?, ?, 100.0,
			?, ?, ?, ?, ?,
			?, ?, ?, 0, 0,
			?, 0, 0, ?,
			0, 0, 0, '', NULL,
			?, ?
		)
		`
		_, err := db.Exec(query,
			h.IP, h.SegmentID, normMAC, h.Hostname, h.VendorModel, h.DisplayName,
			h.OSVendor, h.Status, h.PingRTTMs, h.PingJitterMs,
			h.OpenPorts, h.HTTPTitle, h.UPnPName, h.UPnPModel, h.UPnPSerial,
			h.TLSSubject, h.TLSExpiry, h.MDNSModel,
			h.IsApproved, h.IsDHCP, now, now,
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
		is_approved, is_protected, is_static_ip, is_dhcp,
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
		is_approved, is_protected, is_static_ip, is_dhcp,
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

	db.enrichHostsWithPingHistory(hosts)

	return hosts, rows.Err()
}

func (db *DB) enrichHostsWithPingHistory(hosts []*Host) {
	if len(hosts) == 0 {
		return
	}
	historyMap, err := db.GetBatchPingHistory7d()
	if err != nil {
		return
	}

	for _, h := range hosts {
		items := historyMap[h.IP]
		h.PingChartSVG = RenderSparklineSVG(items, 280, 36)
		h.UptimeBlocksSVG = RenderUptimeBlocksSVG(items, 35)
		h.PingStats7d, _ = ComputePingStats7d(items)
	}
}

// UpdateHostStatus updates the host status and last_seen if up
func (db *DB) UpdateHostStatus(ip string, status string) error {
	now := time.Now()
	var query string
	if status == "up" {
		query = "UPDATE hosts SET status = ?, last_seen = ? WHERE ip = ?"
		_, err := db.Exec(query, status, now, ip)
		return err
	}
	query = "UPDATE hosts SET status = ? WHERE ip = ?"
	_, err := db.Exec(query, status, ip)
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

// CreateManualHost creates a manually defined host
func (db *DB) CreateManualHost(h *Host) error {
	now := time.Now()
	normMAC := strings.ToLower(strings.TrimSpace(h.MACAddress))
	query := `
	INSERT INTO hosts (
		ip, segment_id, mac_address, hostname, vendor_model, display_name,
		os_vendor, status, ping_rtt_ms, ping_jitter_ms, uptime_pct,
		open_ports, http_title, upnp_name, upnp_model, upnp_serial,
		tls_subject, tls_expiry, mdns_model, broadcast_count_1m, is_storming,
		is_approved, is_protected, is_static_ip, is_dhcp,
		is_monitored, is_paused, has_conflict, kuma_name, uptime_kuma_id,
		first_seen, last_seen
	) VALUES (
		?, ?, ?, ?, ?, ?,
		?, ?, ?, ?, 100.0,
		?, ?, ?, ?, ?,
		?, ?, ?, ?, ?,
		?, ?, ?, ?,
		?, ?, ?, ?, ?,
		?, ?
	)
	`
	_, err := db.Exec(query,
		h.IP, h.SegmentID, normMAC, h.Hostname, h.VendorModel, h.DisplayName,
		h.OSVendor, h.Status, h.PingRTTMs, h.PingJitterMs,
		h.OpenPorts, h.HTTPTitle, h.UPnPName, h.UPnPModel, h.UPnPSerial,
		h.TLSSubject, h.TLSExpiry, h.MDNSModel, h.BroadcastCount1m, h.IsStorming,
		h.IsApproved, h.IsProtected, h.IsStaticIP, h.IsDHCP,
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
		&h.IsDHCP,
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

// IsInDHCPRange checks if the given IP address falls within the specified DHCP range.
// Supports full IP range ("192.168.1.100-192.168.1.200") and last-octet range ("100-200").
// Multiple ranges separated by comma are also supported (e.g. "100-150, 180-200").
func IsInDHCPRange(ipStr string, dhcpRange string) bool {
	dhcpRange = strings.TrimSpace(dhcpRange)
	if dhcpRange == "" || ipStr == "" {
		return false
	}

	targetIP := net.ParseIP(ipStr).To4()
	if targetIP == nil {
		return false
	}
	targetVal := ipToUint32(targetIP)
	lastOctet := int(targetIP[3])

	// Split multiple ranges (comma, newline, semicolon)
	parts := strings.FieldsFunc(dhcpRange, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ';'
	})
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}

		// Support hyphen, tilde, wave dash
		delimiter := ""
		if strings.Contains(p, "-") {
			delimiter = "-"
		} else if strings.Contains(p, "~") {
			delimiter = "~"
		} else if strings.Contains(p, "〜") {
			delimiter = "〜"
		} else {
			continue
		}

		rangeParts := strings.SplitN(p, delimiter, 2)
		if len(rangeParts) != 2 {
			continue
		}
		startStr := strings.TrimSpace(rangeParts[0])
		endStr := strings.TrimSpace(rangeParts[1])

		// Case 1: Full IP format ("192.168.1.100-192.168.1.200")
		startIP := net.ParseIP(startStr).To4()
		endIP := net.ParseIP(endStr).To4()
		if startIP != nil && endIP != nil {
			startVal := ipToUint32(startIP)
			endVal := ipToUint32(endIP)
			if startVal <= targetVal && targetVal <= endVal {
				return true
			}
			continue
		}

		// Case 2: Octet range format ("100-200")
		startNum, err1 := strconv.Atoi(startStr)
		endNum, err2 := strconv.Atoi(endStr)
		if err1 == nil && err2 == nil && startNum <= endNum {
			if lastOctet >= startNum && lastOctet <= endNum {
				return true
			}
		}
	}

	return false
}

func ipToUint32(ip net.IP) uint32 {
	return uint32(ip[0])<<24 | uint32(ip[1])<<16 | uint32(ip[2])<<8 | uint32(ip[3])
}

// GuessDHCPRange estimates a probable DHCP pool range based on detected client/Wi-Fi host IPs
func GuessDHCPRange(hosts []*Host, cidr string) string {
	if len(hosts) == 0 {
		return "100-200"
	}

	var octets []int
	for _, h := range hosts {
		ip := net.ParseIP(h.IP).To4()
		if ip == nil {
			continue
		}
		oct := int(ip[3])
		// Exclude router (.1), broadcast (.255), and typical network devices (.254)
		if oct <= 1 || oct >= 254 {
			continue
		}

		// Give priority to Wi-Fi devices, smartphones, and computers
		if h.ConnectionType() == "wifi" || strings.Contains(strings.ToLower(h.VendorModel), "apple") || strings.Contains(strings.ToLower(h.OSVendor), "android") || strings.Contains(strings.ToLower(h.OSVendor), "windows") {
			octets = append(octets, oct)
		}
	}

	if len(octets) == 0 {
		// Fallback to non-infrastructure devices
		for _, h := range hosts {
			ip := net.ParseIP(h.IP).To4()
			if ip == nil {
				continue
			}
			oct := int(ip[3])
			if oct > 10 && oct < 250 {
				octets = append(octets, oct)
			}
		}
	}

	if len(octets) == 0 {
		return "100-200"
	}

	sort.Ints(octets)
	minOct := octets[0]
	maxOct := octets[len(octets)-1]

	// Round to intuitive bounds (e.g. min 105 -> 100, max 165 -> 200)
	var startBound, endBound int
	if minOct >= 100 {
		startBound = 100
	} else if minOct >= 50 {
		startBound = 50
	} else if minOct >= 2 {
		startBound = 2
	} else {
		startBound = 100
	}

	if maxOct <= 100 && startBound < 100 {
		endBound = 100
	} else if maxOct <= 150 {
		endBound = 150
	} else if maxOct <= 200 {
		endBound = 200
	} else {
		endBound = 250
	}

	if startBound >= endBound {
		return "100-200"
	}

	return fmt.Sprintf("%d-%d", startBound, endBound)
}

// ToggleHostDHCP toggles the is_dhcp status of a host
func (db *DB) ToggleHostDHCP(ip string) (bool, error) {
	host, err := db.GetHost(ip)
	if err != nil {
		return false, err
	}
	if host == nil {
		return false, fmt.Errorf("host not found: %s", ip)
	}

	newStatus := !host.IsDHCP
	_, err = db.Exec("UPDATE hosts SET is_dhcp = ? WHERE ip = ?", newStatus, ip)
	return newStatus, err
}

// AutoAdjustSegmentDHCPRange recalculates and updates the segment's DHCP range
// based on hosts explicitly marked as is_dhcp=true and Wi-Fi clients
func (db *DB) AutoAdjustSegmentDHCPRange(segID int64) (string, error) {
	seg, err := db.GetSegment(segID)
	if err != nil {
		return "", err
	}
	if seg == nil {
		return "", fmt.Errorf("segment not found: %d", segID)
	}

	// Skip auto-adjustment if the user has manually fixed the DHCP range
	if seg.IsDHCPManual {
		return seg.DHCPRange, nil
	}

	hosts, err := db.ListHosts(&segID, false)
	if err != nil {
		return "", err
	}

	// Also find any hosts matching by CIDR if segment_id wasn't set
	if seg.CIDR != "" {
		allHosts, _ := db.ListHosts(nil, false)
		_, cidrNet, err := net.ParseCIDR(seg.CIDR)
		if err == nil {
			existingIPs := make(map[string]bool)
			for _, h := range hosts {
				existingIPs[h.IP] = true
			}
			for _, h := range allHosts {
				if !existingIPs[h.IP] {
					if pIP := net.ParseIP(h.IP); pIP != nil && cidrNet.Contains(pIP) {
						hosts = append(hosts, h)
					}
				}
			}
		}
	}

	// Find DHCP-marked hosts or Wi-Fi hosts
	var dhcpHosts []*Host
	for _, h := range hosts {
		if h.IsDHCP || h.ConnectionType() == "wifi" {
			dhcpHosts = append(dhcpHosts, h)
		}
	}

	if len(dhcpHosts) == 0 {
		return seg.DHCPRange, nil
	}

	newRange := GuessDHCPRange(dhcpHosts, seg.CIDR)
	if newRange != "" && newRange != seg.DHCPRange {
		seg.DHCPRange = newRange
		_ = db.UpdateSegment(seg)
	}
	return newRange, nil
}
