package db

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func setupTestDB(t *testing.T) *DB {
	t.Helper()
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_lanmap.db")
	db, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open DB failed: %v", err)
	}
	t.Cleanup(func() {
		db.Close()
	})
	return db
}

func TestDBInitAndSeed(t *testing.T) {
	db := setupTestDB(t)

	// Check default segment
	defSeg, err := db.GetDefaultSegment()
	if err != nil {
		t.Fatalf("GetDefaultSegment failed: %v", err)
	}
	if defSeg == nil {
		t.Fatal("expected default segment to exist, got nil")
	}
	if defSeg.Name != "未分類" || !defSeg.IsDefault {
		t.Errorf("unexpected default segment: %+v", defSeg)
	}

	// Check retention days seed (default 3 days)
	retDays, err := db.GetRetentionDays()
	if err != nil {
		t.Fatalf("GetRetentionDays failed: %v", err)
	}
	if retDays != 3 {
		t.Errorf("expected retention days 3, got %d", retDays)
	}
}

func TestSegmentOperations(t *testing.T) {
	db := setupTestDB(t)

	// Create valid segment
	seg, err := db.CreateSegment("Office LAN", "192.168.1.0/24", "eth0", true)
	if err != nil {
		t.Fatalf("CreateSegment failed: %v", err)
	}
	if seg.ID == 0 || seg.Name != "Office LAN" {
		t.Errorf("unexpected segment: %+v", seg)
	}

	// Create segment with invalid CIDR
	_, err = db.CreateSegment("Bad CIDR", "invalid_cidr", "", true)
	if err == nil {
		t.Error("expected error on invalid CIDR, got nil")
	}

	// Check CIDR overlap
	overlaps, err := db.CheckCIDROverlap("192.168.1.128/25", 0)
	if err != nil {
		t.Fatalf("CheckCIDROverlap failed: %v", err)
	}
	if len(overlaps) != 1 || overlaps[0].ID != seg.ID {
		t.Errorf("expected 1 overlapping segment, got: %d", len(overlaps))
	}

	// Test FindSegmentForIP
	matchSeg, err := db.FindSegmentForIP(net.ParseIP("192.168.1.50"))
	if err != nil {
		t.Fatalf("FindSegmentForIP failed: %v", err)
	}
	if matchSeg == nil || matchSeg.ID != seg.ID {
		t.Errorf("expected match segment %d, got %+v", seg.ID, matchSeg)
	}

	// Test fallback to default segment for unmanaged IP
	unmanagedSeg, err := db.FindSegmentForIP(net.ParseIP("10.0.0.1"))
	if err != nil {
		t.Fatalf("FindSegmentForIP for unmanaged failed: %v", err)
	}
	if unmanagedSeg == nil || !unmanagedSeg.IsDefault {
		t.Errorf("expected default segment for unmanaged IP, got %+v", unmanagedSeg)
	}

	// Cannot delete default segment
	defSeg, _ := db.GetDefaultSegment()
	err = db.DeleteSegment(defSeg.ID)
	if err == nil {
		t.Error("expected error deleting default segment, got nil")
	}

	// Delete custom segment
	err = db.DeleteSegment(seg.ID)
	if err != nil {
		t.Fatalf("DeleteSegment failed: %v", err)
	}
	deleted, _ := db.GetSegment(seg.ID)
	if deleted != nil {
		t.Error("expected segment to be deleted, got non-nil")
	}
}

func TestHostUpsertAndMACReuse(t *testing.T) {
	db := setupTestDB(t)

	// 1. Insert new host
	h1 := &Host{
		IP:          "192.168.1.100",
		MACAddress:  "aa:bb:cc:11:22:33",
		Hostname:    "pc-alice",
		VendorModel: "Apple MacBook Pro",
	}
	isNew, isReplaced, err := db.UpsertHostOnScan(h1)
	if err != nil {
		t.Fatalf("UpsertHostOnScan 1 failed: %v", err)
	}
	if !isNew || isReplaced {
		t.Errorf("expected isNew=true, isReplaced=false, got isNew=%v, isReplaced=%v", isNew, isReplaced)
	}

	// Approve the host
	approved, err := db.ToggleApproval(h1.IP)
	if err != nil || !approved {
		t.Fatalf("ToggleApproval failed: %v", err)
	}

	// 2. Re-scan same host (same MAC)
	h1ReScan := &Host{
		IP:          "192.168.1.100",
		MACAddress:  "aa:bb:cc:11:22:33",
		Hostname:    "pc-alice-renamed",
		VendorModel: "Apple MacBook Pro",
	}
	isNew, isReplaced, err = db.UpsertHostOnScan(h1ReScan)
	if err != nil {
		t.Fatalf("UpsertHostOnScan rescan failed: %v", err)
	}
	if isNew || isReplaced {
		t.Errorf("expected isNew=false, isReplaced=false, got isNew=%v, isReplaced=%v", isNew, isReplaced)
	}

	stored, err := db.GetHost(h1.IP)
	if err != nil || stored == nil {
		t.Fatalf("GetHost failed: %v", err)
	}
	if !stored.IsApproved {
		t.Error("expected host to remain approved on same MAC rescan")
	}
	if stored.Hostname != "pc-alice-renamed" {
		t.Errorf("expected hostname updated to pc-alice-renamed, got %s", stored.Hostname)
	}

	// 3. DHCP IP reuse with DIFFERENT MAC address
	// New device is inserted as up, previous device is retained with status='down'
	h1DifferentMAC := &Host{
		IP:          "192.168.1.100",
		MACAddress:  "dd:ee:ff:44:55:66",
		Hostname:    "unknown-device",
		VendorModel: "Unknown Vendor",
		Status:      "up",
	}
	isNew, isReplaced, err = db.UpsertHostOnScan(h1DifferentMAC)
	if err != nil {
		t.Fatalf("UpsertHostOnScan with different MAC failed: %v", err)
	}
	if !isNew || !isReplaced {
		t.Errorf("expected isNew=true, isReplaced=true on new MAC on same IP, got isNew=%v, isReplaced=%v", isNew, isReplaced)
	}

	storedAfterReuse, err := db.GetHost(h1.IP)
	if err != nil || storedAfterReuse == nil {
		t.Fatalf("GetHost after reuse failed: %v", err)
	}
	if storedAfterReuse.MACAddress != "dd:ee:ff:44:55:66" {
		t.Errorf("expected active host to be new MAC dd:ee:ff:44:55:66, got %s", storedAfterReuse.MACAddress)
	}
	if storedAfterReuse.Status != "up" {
		t.Errorf("expected active host status to be up, got %s", storedAfterReuse.Status)
	}

	// Verify old host is retained in DB as status='down'
	oldHost, err := db.GetHostByMAC("aa:bb:cc:11:22:33")
	if err != nil || oldHost == nil {
		t.Fatalf("GetHostByMAC for previous host failed: %v", err)
	}
	if oldHost.Status != "down" {
		t.Errorf("expected previous host to have status='down', got %s", oldHost.Status)
	}

	// Verify ListHosts returns both hosts and marks previous host
	allHosts, err := db.ListHosts(nil, false)
	if err != nil {
		t.Fatalf("ListHosts failed: %v", err)
	}
	if len(allHosts) < 2 {
		t.Errorf("expected at least 2 hosts (new and previous), got %d", len(allHosts))
	}
	var foundPrev bool
	for _, h := range allHosts {
		if h.MACAddress == "aa:bb:cc:11:22:33" && h.IsPreviousHost {
			foundPrev = true
		}
	}
	if !foundPrev {
		t.Error("expected previous host to have IsPreviousHost=true")
	}
}

func TestListHostsDaysFilter(t *testing.T) {
	db := setupTestDB(t)

	now := time.Now()
	// Host 1: online
	h1 := &Host{
		IP:         "192.168.1.10",
		MACAddress: "aa:11:11:11:11:11",
		Status:     "up",
	}
	_, _, _ = db.UpsertHostOnScan(h1)

	// Host 2: offline 2 days ago
	twoDaysAgo := now.Add(-48 * time.Hour)
	_, _ = db.Exec("INSERT INTO hosts (ip, mac_address, status, first_seen, last_seen) VALUES (?, ?, 'down', ?, ?)",
		"192.168.1.20", "bb:22:22:22:22:22", twoDaysAgo, twoDaysAgo)

	// Host 3: offline 5 days ago
	fiveDaysAgo := now.Add(-120 * time.Hour)
	_, _ = db.Exec("INSERT INTO hosts (ip, mac_address, status, first_seen, last_seen) VALUES (?, ?, 'down', ?, ?)",
		"192.168.1.30", "cc:33:33:33:33:33", fiveDaysAgo, fiveDaysAgo)

	// Host 4: offline 10 days ago
	tenDaysAgo := now.Add(-240 * time.Hour)
	_, _ = db.Exec("INSERT INTO hosts (ip, mac_address, status, first_seen, last_seen) VALUES (?, ?, 'down', ?, ?)",
		"192.168.1.40", "dd:44:44:44:44:44", tenDaysAgo, tenDaysAgo)

	// 1. Online only filter
	onlineHosts, err := db.ListHostsFiltered(nil, "online", 0)
	if err != nil {
		t.Fatalf("ListHostsFiltered online failed: %v", err)
	}
	if len(onlineHosts) != 1 || onlineHosts[0].IP != "192.168.1.10" {
		t.Errorf("expected 1 online host, got %d", len(onlineHosts))
	}

	// 2. 3 days filter (should include online + 2 days ago = 2 hosts)
	hosts3d, err := db.ListHostsFiltered(nil, "days", 3)
	if err != nil {
		t.Fatalf("ListHostsFiltered 3d failed: %v", err)
	}
	if len(hosts3d) != 2 {
		t.Errorf("expected 2 hosts for 3-day filter, got %d", len(hosts3d))
	}

	// 3. 7 days filter (should include online + 2 days + 5 days = 3 hosts)
	hosts7d, err := db.ListHostsFiltered(nil, "days", 7)
	if err != nil {
		t.Fatalf("ListHostsFiltered 7d failed: %v", err)
	}
	if len(hosts7d) != 3 {
		t.Errorf("expected 3 hosts for 7-day filter, got %d", len(hosts7d))
	}

	// 4. All filter (should include all 4 hosts)
	hostsAll, err := db.ListHostsFiltered(nil, "all", 0)
	if err != nil {
		t.Fatalf("ListHostsFiltered all failed: %v", err)
	}
	if len(hostsAll) != 4 {
		t.Errorf("expected 4 hosts for all filter, got %d", len(hostsAll))
	}
}

func TestHostUpsertDHCPSupport(t *testing.T) {
	db := setupTestDB(t)

	// 1. Initial insert with is_dhcp=false
	h1 := &Host{
		IP:          "192.168.1.88",
		MACAddress:  "11:22:33:44:55:66",
		Hostname:    "device-88",
		IsDHCP:      false,
		Status:      "up",
	}
	_, _, err := db.UpsertHostOnScan(h1)
	if err != nil {
		t.Fatalf("UpsertHostOnScan failed: %v", err)
	}

	stored, _ := db.GetHost("192.168.1.88")
	if stored.IsDHCP {
		t.Errorf("expected initial is_dhcp=false, got true")
	}

	// 2. DHCP event arrives with is_dhcp=true
	h1DHCP := &Host{
		IP:          "192.168.1.88",
		MACAddress:  "11:22:33:44:55:66",
		Hostname:    "device-88-dhcp",
		IsDHCP:      true,
		Status:      "up",
	}
	_, _, err = db.UpsertHostOnScan(h1DHCP)
	if err != nil {
		t.Fatalf("UpsertHostOnScan rescan failed: %v", err)
	}

	stored2, _ := db.GetHost("192.168.1.88")
	if !stored2.IsDHCP {
		t.Errorf("expected is_dhcp to be updated to true, got false")
	}
	if stored2.Hostname != "device-88-dhcp" {
		t.Errorf("expected hostname updated, got %s", stored2.Hostname)
	}
}

func TestHostCleanupProtection(t *testing.T) {
	db := setupTestDB(t)

	// Helper to insert host with old last_seen
	insertOldHost := func(ip, mac string, isProtected, isMonitored, isStatic, isApproved bool) {
		oldTime := time.Now().UTC().AddDate(0, 0, -200) // 200 days ago
		query := `
		INSERT INTO hosts (
			ip, mac_address, status, is_protected, is_monitored, is_static_ip, is_approved, first_seen, last_seen
		) VALUES (?, ?, 'down', ?, ?, ?, ?, ?, ?)
		`
		_, err := db.Exec(query, ip, mac, isProtected, isMonitored, isStatic, isApproved, oldTime, oldTime)
		if err != nil {
			t.Fatalf("failed to insert old host: %v", err)
		}
	}

	// 1. Unprotected old host -> should be deleted
	insertOldHost("192.168.1.1", "11:11:11:11:11:11", false, false, false, false)

	// 2. Protected host (is_protected=1) -> should NOT be deleted
	insertOldHost("192.168.1.2", "22:22:22:22:22:22", true, false, false, false)

	// 3. Static IP host (is_static_ip=1) -> should NOT be deleted
	insertOldHost("192.168.1.4", "44:44:44:44:44:44", false, false, true, false)

	// 4. Approved host (is_approved=1) -> should NOT be deleted
	insertOldHost("192.168.1.5", "55:55:55:55:55:55", false, false, false, true)

	// 5. Multiple flags (protected + approved) -> should NOT be deleted
	insertOldHost("192.168.1.6", "66:66:66:66:66:66", true, false, false, true)

	// Run cleanup for > 180 days
	deletedCount, err := db.CleanupOldHosts(180)
	if err != nil {
		t.Fatalf("CleanupOldHosts failed: %v", err)
	}

	if deletedCount != 1 {
		t.Errorf("expected 1 host deleted, got %d", deletedCount)
	}

	// Verify host 1 was deleted
	h1, _ := db.GetHost("192.168.1.1")
	if h1 != nil {
		t.Error("host 192.168.1.1 was not deleted")
	}

	// Verify protected hosts still exist
	for _, ip := range []string{"192.168.1.2", "192.168.1.4", "192.168.1.5", "192.168.1.6"} {
		h, _ := db.GetHost(ip)
		if h == nil {
			t.Errorf("protected host %s was unexpectedly deleted", ip)
		}
	}

	// When retention is 0 (disabled), 0 rows should be deleted
	deletedDisabled, err := db.CleanupOldHosts(0)
	if err != nil || deletedDisabled != 0 {
		t.Errorf("expected 0 deleted when retention is 0, got %d, err=%v", deletedDisabled, err)
	}
}

func TestSettingsCRUD(t *testing.T) {
	db := setupTestDB(t)

	err := db.SetSetting("webhook_slack_url", "https://hooks.slack.com/services/xxx")
	if err != nil {
		t.Fatalf("SetSetting failed: %v", err)
	}

	val, err := db.GetSetting("webhook_slack_url")
	if err != nil || val != "https://hooks.slack.com/services/xxx" {
		t.Errorf("expected slack webhook url, got %s, err=%v", val, err)
	}

	all, err := db.GetAllSettings()
	if err != nil {
		t.Fatalf("GetAllSettings failed: %v", err)
	}
	if all["webhook_slack_url"] != "https://hooks.slack.com/services/xxx" {
		t.Errorf("missing webhook_slack_url in all settings")
	}

	// Test PortScanEnabled (default is false)
	isPortScan, err := db.IsPortScanEnabled()
	if err != nil {
		t.Fatalf("IsPortScanEnabled failed: %v", err)
	}
	if isPortScan != false {
		t.Errorf("expected default IsPortScanEnabled to be false (Safe Mode), got %v", isPortScan)
	}

	if err := db.SetPortScanEnabled(true); err != nil {
		t.Fatalf("SetPortScanEnabled true failed: %v", err)
	}
	isPortScan, _ = db.IsPortScanEnabled()
	if isPortScan != true {
		t.Errorf("expected IsPortScanEnabled to be true after set, got %v", isPortScan)
	}

	if err := db.SetPortScanEnabled(false); err != nil {
		t.Fatalf("SetPortScanEnabled false failed: %v", err)
	}
	isPortScan, _ = db.IsPortScanEnabled()
	if isPortScan != false {
		t.Errorf("expected IsPortScanEnabled to be false after set, got %v", isPortScan)
	}

	// Test 3-Tier ScanMode
	mode, err := db.GetScanMode()
	if err != nil {
		t.Fatalf("GetScanMode failed: %v", err)
	}
	if mode != ScanModeStealth {
		t.Errorf("expected default ScanMode to be stealth, got %s", mode)
	}

	_ = db.SetScanMode(ScanModeSafe)
	mode, _ = db.GetScanMode()
	if mode != ScanModeSafe {
		t.Errorf("expected ScanMode to be safe, got %s", mode)
	}

	_ = db.SetScanMode(ScanModeFull)
	mode, _ = db.GetScanMode()
	if mode != ScanModeFull {
		t.Errorf("expected ScanMode to be full, got %s", mode)
	}
	isPS, _ := db.IsPortScanEnabled()
	if !isPS {
		t.Errorf("expected IsPortScanEnabled to be true when mode is full")
	}

	_ = db.SetScanMode(ScanModeStealth)
	mode, _ = db.GetScanMode()
	if mode != ScanModeStealth {
		t.Errorf("expected ScanMode to be stealth, got %s", mode)
	}
	isPS, _ = db.IsPortScanEnabled()
	if isPS {
		t.Errorf("expected IsPortScanEnabled to be false when mode is stealth")
	}

	// Test UpdateHostExtendedProbes
	hTest := &Host{IP: "192.168.1.150", MACAddress: "aa:bb:cc:11:22:33", Hostname: "test-box"}
	_, _, err = db.UpsertHostOnScan(hTest)
	if err != nil {
		t.Fatalf("UpsertHostOnScan failed: %v", err)
	}

	err = db.UpdateHostExtendedProbes("192.168.1.150", "80:HTTP,443:HTTPS", "Welcome Server", "TestUPnP", "ModelX", "SN123", "server.local", nil)
	if err != nil {
		t.Fatalf("UpdateHostExtendedProbes failed: %v", err)
	}

	hFetched, err := db.GetHost("192.168.1.150")
	if err != nil || hFetched == nil {
		t.Fatalf("GetHost failed: %v", err)
	}
	if hFetched.OpenPorts != "80:HTTP,443:HTTPS" || hFetched.HTTPTitle != "Welcome Server" {
		t.Errorf("unexpected probed host fields: open_ports=%s, http_title=%s", hFetched.OpenPorts, hFetched.HTTPTitle)
	}

	// Verify safe mode rescan does not wipe out previously probed open ports
	hRescanSafe := &Host{IP: "192.168.1.150", MACAddress: "aa:bb:cc:11:22:33", Hostname: "test-box-updated"}
	_, _, err = db.UpsertHostOnScan(hRescanSafe)
	if err != nil {
		t.Fatalf("UpsertHostOnScan safe mode failed: %v", err)
	}
	hAfterSafe, _ := db.GetHost("192.168.1.150")
	if hAfterSafe.OpenPorts != "80:HTTP,443:HTTPS" || hAfterSafe.HTTPTitle != "Welcome Server" {
		t.Errorf("open_ports or http_title wiped out by safe mode scan: open_ports=%s, http_title=%s", hAfterSafe.OpenPorts, hAfterSafe.HTTPTitle)
	}
}

func TestHostOpenPortsParsing(t *testing.T) {
	h := &Host{
		OpenPorts: "22:SSH,80:HTTP,443:HTTPS",
	}

	if !h.HasOpenPorts() {
		t.Error("expected HasOpenPorts to be true")
	}

	list := h.OpenPortsList()
	if len(list) != 3 {
		t.Fatalf("expected 3 ports, got %d", len(list))
	}

	if list[0].Port != 22 || list[0].Service != "SSH" {
		t.Errorf("unexpected port 0: %+v", list[0])
	}
	if list[1].Port != 80 || list[1].Service != "HTTP" {
		t.Errorf("unexpected port 1: %+v", list[1])
	}
}

func TestHostExtendedFields(t *testing.T) {
	exp := time.Now().Add(10 * 24 * time.Hour)
	h := &Host{
		TLSSubject: "synology.lan",
		TLSExpiry:  &exp,
	}

	if !h.HasTLS() {
		t.Error("expected HasTLS to be true")
	}
	if !h.TLSExpiresSoon() {
		t.Error("expected TLSExpiresSoon to be true for 10 days remaining")
	}
	if days := h.DaysUntilTLSExpiry(); days < 9 || days > 11 {
		t.Errorf("unexpected days until expiry: %d", days)
	}
}

func TestPingHistoryAndSVGRendering(t *testing.T) {
	db := setupTestDB(t)

	rtt1 := 1.5
	rtt2 := 2.8
	rtt3 := 1.2
	_ = db.RecordPingHistory("192.168.1.100", &rtt1, "up")
	_ = db.RecordPingHistory("192.168.1.100", &rtt2, "up")
	_ = db.RecordPingHistory("192.168.1.100", nil, "down")
	_ = db.RecordPingHistory("192.168.1.100", &rtt3, "up")

	history, err := db.GetHostPingHistory("192.168.1.100", 7*24*time.Hour)
	if err != nil {
		t.Fatalf("GetHostPingHistory failed: %v", err)
	}
	if len(history) != 4 {
		t.Fatalf("expected 4 history items, got %d", len(history))
	}

	svg := RenderSparklineSVG(history, 280, 36)
	if len(svg) == 0 {
		t.Error("expected non-empty SVG sparkline")
	}

	uptimeSVG := RenderUptimeBlocksSVG(history, 10)
	if len(uptimeSVG) == 0 {
		t.Error("expected non-empty Uptime blocks SVG")
	}

	stats, upPct := ComputePingStats7d(history)
	if upPct != 75.0 {
		t.Errorf("expected 75%% uptime, got %.1f%%", upPct)
	}
	if len(stats) == 0 {
		t.Error("expected non-empty stats string")
	}

	// Test 7-day SVG and detailed metrics
	svg7d := RenderSparkline7dSVG(history, 600, 120)
	if len(svg7d) == 0 {
		t.Error("expected non-empty 7-day SVG sparkline")
	}

	blocks7d := RenderUptimeBlocks7dSVG(history, 42)
	if len(blocks7d) == 0 {
		t.Error("expected non-empty 7-day uptime blocks")
	}

	stats7d := ComputePingStats7dDetails(history)
	if stats7d.TotalProbes != 4 {
		t.Errorf("expected 4 probes in 7d stats, got %d", stats7d.TotalProbes)
	}
	if stats7d.UpCount != 3 || stats7d.DownCount != 1 {
		t.Errorf("expected 3 up, 1 down, got up=%d, down=%d", stats7d.UpCount, stats7d.DownCount)
	}
	if stats7d.UptimePct != 75.0 {
		t.Errorf("expected 75%% uptime percentage, got %f", stats7d.UptimePct)
	}

	// Test purge
	err = db.PurgeOldPingHistory(7)
	if err != nil {
		t.Fatalf("PurgeOldPingHistory failed: %v", err)
	}
}

func TestPingHistorySleepGapPartitioning(t *testing.T) {
	now := time.Now().UTC()
	rtt1 := 1.2
	rtt2 := 1.5
	rtt3 := 2.0
	rtt4 := 1.8

	// Create items with an 8-hour sleep gap in between
	items := []PingHistoryItem{
		// Before sleep: 10h ago
		{ID: 1, HostIP: "192.168.1.50", RTTMs: &rtt1, Status: "up", CreatedAt: now.Add(-10 * time.Hour)},
		{ID: 2, HostIP: "192.168.1.50", RTTMs: &rtt2, Status: "up", CreatedAt: now.Add(-9 * time.Hour - 55*time.Minute)},
		// Sleep gap: 8 hours without data...
		// After wake: 1h ago
		{ID: 3, HostIP: "192.168.1.50", RTTMs: &rtt3, Status: "up", CreatedAt: now.Add(-1 * time.Hour)},
		{ID: 4, HostIP: "192.168.1.50", RTTMs: &rtt4, Status: "up", CreatedAt: now.Add(-55 * time.Minute)},
	}

	// 7-day SVG
	svg7d := string(RenderSparkline7dSVG(items, 920, 200))
	// Count polylines (must be 2 distinct segments, NOT 1 continuous line)
	polylineCount := strings.Count(svg7d, "<polyline")
	if polylineCount != 2 {
		t.Errorf("expected 2 distinct polyline segments due to sleep gap, got %d", polylineCount)
	}
	polygonCount := strings.Count(svg7d, "<polygon")
	if polygonCount != 2 {
		t.Errorf("expected 2 distinct filled polygons, got %d", polygonCount)
	}
	// Must have dashed line for the gap
	if !strings.Contains(svg7d, `stroke-dasharray="3,3"`) {
		t.Error("expected dashed line for unmeasured sleep gap")
	}

	// 24-hour SVG
	svg24h := string(RenderSparkline24hSVG(items, 280, 36))
	polylineCount24h := strings.Count(svg24h, "<polyline")
	if polylineCount24h != 2 {
		t.Errorf("expected 2 distinct polyline segments in 24h chart, got %d", polylineCount24h)
	}
	if !strings.Contains(svg24h, `stroke-dasharray="3,3"`) {
		t.Error("expected dashed line for sleep gap in 24h chart")
	}
}

func TestConnectionTypeDetection(t *testing.T) {
	// 1. Mobile (iPhone / iPad) -> Wi-Fi
	h1 := &Host{
		Hostname:  "iphone.local",
		MDNSModel: "iPhone 16 Pro",
	}
	if h1.ConnectionType() != "wifi" {
		t.Errorf("expected h1 wifi, got %s", h1.ConnectionType())
	}

	// 2. Randomized MAC -> Wi-Fi
	h2 := &Host{
		MACAddress: "3a:88:12:34:56:78", // 2nd char 'a' -> randomized
	}
	if !h2.IsRandomizedMAC() {
		t.Error("expected h2 randomized MAC")
	}
	if h2.ConnectionType() != "wifi" {
		t.Errorf("expected h2 wifi, got %s", h2.ConnectionType())
	}

	// 3. Infrastructure (OpenWrt / Synology) -> Ethernet
	h3 := &Host{
		Hostname: "openwrt.lan",
	}
	if h3.ConnectionType() != "ethernet" {
		t.Errorf("expected h3 ethernet, got %s", h3.ConnectionType())
	}

	// 4. Low latency wired PC (<0.8ms) -> Ethernet
	rttFast := 0.35
	jitterFast := 0.05
	h4 := &Host{
		PingRTTMs:    &rttFast,
		PingJitterMs: &jitterFast,
	}
	if h4.ConnectionType() != "ethernet" {
		t.Errorf("expected h4 ethernet, got %s", h4.ConnectionType())
	}

	// 5. Higher latency Wi-Fi (>1.5ms) -> Wi-Fi
	rttSlow := 4.5
	jitterSlow := 1.2
	h5 := &Host{
		PingRTTMs:    &rttSlow,
		PingJitterMs: &jitterSlow,
	}
	if h5.ConnectionType() != "wifi" {
		t.Errorf("expected h5 wifi, got %s", h5.ConnectionType())
	}

	// 6. Network Infrastructure (Netgear AP / Router) -> Ethernet (overrides Wi-Fi jitter)
	h6 := &Host{
		VendorModel:  "Netgear",
		PingRTTMs:    &rttSlow,
		PingJitterMs: &jitterSlow,
	}
	if h6.ConnectionType() != "ethernet" {
		t.Errorf("expected h6 ethernet for Netgear, got %s", h6.ConnectionType())
	}
	if h6.ConnectionReason() != "ネットワーク機器 (AP/ルーター)" {
		t.Errorf("expected network device reason, got %s", h6.ConnectionReason())
	}
}

func TestDHCPRangeAndGuess(t *testing.T) {
	// 1. Test IsInDHCPRange with octet range
	if !IsInDHCPRange("192.168.1.100", "100-200") {
		t.Errorf("expected 192.168.1.100 to be in 100-200")
	}
	if !IsInDHCPRange("192.168.1.150", "100-200") {
		t.Errorf("expected 192.168.1.150 to be in 100-200")
	}
	if !IsInDHCPRange("192.168.1.200", "100-200") {
		t.Errorf("expected 192.168.1.200 to be in 100-200")
	}
	if IsInDHCPRange("192.168.1.99", "100-200") {
		t.Errorf("expected 192.168.1.99 NOT to be in 100-200")
	}
	if IsInDHCPRange("192.168.1.201", "100-200") {
		t.Errorf("expected 192.168.1.201 NOT to be in 100-200")
	}

	// 2. Test IsInDHCPRange with full IP range
	if !IsInDHCPRange("10.0.0.50", "10.0.0.20-10.0.0.80") {
		t.Errorf("expected 10.0.0.50 to be in 10.0.0.20-10.0.0.80")
	}
	if IsInDHCPRange("10.0.0.10", "10.0.0.20-10.0.0.80") {
		t.Errorf("expected 10.0.0.10 NOT to be in 10.0.0.20-10.0.0.80")
	}

	// 3. Test IsInDHCPRange with comma-separated ranges
	if !IsInDHCPRange("192.168.1.10", "10-20, 100-200") {
		t.Errorf("expected 192.168.1.10 to match first range")
	}
	if !IsInDHCPRange("192.168.1.150", "10-20, 100-200") {
		t.Errorf("expected 192.168.1.150 to match second range")
	}
	if IsInDHCPRange("192.168.1.50", "10-20, 100-200") {
		t.Errorf("expected 192.168.1.50 NOT to be in 10-20, 100-200")
	}

	// 3.1 Test Prefix Range with /23 subnet (e.g. 192.168.0.100-200 and 192.168.1.150-200)
	slash23Range := "192.168.0.100-200, 192.168.1.150-200"
	if !IsInDHCPRange("192.168.0.100", slash23Range) {
		t.Errorf("expected 192.168.0.100 to be in range")
	}
	if !IsInDHCPRange("192.168.0.150", slash23Range) {
		t.Errorf("expected 192.168.0.150 to be in range")
	}
	if !IsInDHCPRange("192.168.0.200", slash23Range) {
		t.Errorf("expected 192.168.0.200 to be in range")
	}
	if !IsInDHCPRange("192.168.1.150", slash23Range) {
		t.Errorf("expected 192.168.1.150 to be in range")
	}
	if !IsInDHCPRange("192.168.1.200", slash23Range) {
		t.Errorf("expected 192.168.1.200 to be in range")
	}
	if IsInDHCPRange("192.168.0.50", slash23Range) {
		t.Errorf("expected 192.168.0.50 NOT to be in range")
	}
	if IsInDHCPRange("192.168.1.100", slash23Range) {
		t.Errorf("expected 192.168.1.100 NOT to be in range (only 150-200)")
	}
	if IsInDHCPRange("192.168.2.150", slash23Range) {
		t.Errorf("expected 192.168.2.150 NOT to be in range")
	}

	// 4. Test GuessDHCPRange
	hosts := []*Host{
		{IP: "192.168.1.1", VendorModel: "Yamaha RTX1210"}, // Router
		{IP: "192.168.1.2", VendorModel: "Canon Printer"},
		{IP: "192.168.1.105", OSVendor: "iOS", VendorModel: "Apple iPhone 15"},
		{IP: "192.168.1.140", OSVendor: "Android", VendorModel: "Google Pixel 8"},
		{IP: "192.168.1.180", OSVendor: "macOS", VendorModel: "Apple MacBook Pro"},
	}
	guess := GuessDHCPRange(hosts, "192.168.1.0/24")
	if guess != "100-200" {
		t.Errorf("expected guess 100-200, got %s", guess)
	}

	// 5. Test Segment CRUD with DHCPRange
	tempDir := t.TempDir()
	testDB, err := Open(filepath.Join(tempDir, "test_dhcp.db"))
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer testDB.Close()

	seg, err := testDB.CreateSegmentWithDHCP("Office LAN", "192.168.1.0/24", "eth0", true, "100-200", false)
	if err != nil {
		t.Fatalf("CreateSegmentWithDHCP failed: %v", err)
	}
	if seg.DHCPRange != "100-200" {
		t.Errorf("expected DHCPRange 100-200, got %s", seg.DHCPRange)
	}

	seg.DHCPRange = "150-250"
	_ = testDB.UpdateSegment(seg)

	updated, _ := testDB.GetSegment(seg.ID)
	if updated.DHCPRange != "150-250" {
		t.Errorf("expected updated DHCPRange 150-250, got %s", updated.DHCPRange)
	}

	// 6. Test ToggleHostDHCP and AutoAdjustSegmentDHCPRange
	_ = testDB.CreateManualHost(&Host{
		IP:          "192.168.1.110",
		SegmentID:   &seg.ID,
		DisplayName: "Test Host 110",
		IsDHCP:      false,
	})
	_ = testDB.CreateManualHost(&Host{
		IP:          "192.168.1.160",
		SegmentID:   &seg.ID,
		DisplayName: "Test Host 160",
		IsDHCP:      false,
	})

	toggled, err := testDB.ToggleHostDHCP("192.168.1.110")
	if err != nil || !toggled {
		t.Fatalf("ToggleHostDHCP failed: %v", err)
	}
	h110, _ := testDB.GetHost("192.168.1.110")
	if !h110.IsDHCP {
		t.Errorf("expected h110 IsDHCP to be true")
	}

	_, _ = testDB.ToggleHostDHCP("192.168.1.160")

	// Test AutoAdjustSegmentDHCPRange (when not manual)
	newRange, err := testDB.AutoAdjustSegmentDHCPRange(seg.ID)
	if err != nil {
		t.Fatalf("AutoAdjustSegmentDHCPRange failed: %v", err)
	}
	if newRange != "100-200" {
		t.Errorf("expected auto adjusted range 100-200, got %s", newRange)
	}

	// Test AutoAdjustSegmentDHCPRange skipped when IsDHCPManual is true
	seg.IsDHCPManual = true
	seg.DHCPRange = "120-130"
	_ = testDB.UpdateSegment(seg)

	skippedRange, err := testDB.AutoAdjustSegmentDHCPRange(seg.ID)
	if err != nil || skippedRange != "120-130" {
		t.Errorf("expected auto adjust to be skipped for manual segment, got %s", skippedRange)
	}

	// Test multiple ranges with newline and semicolon
	if !IsInDHCPRange("192.168.1.125", "10-20\n120-130;200-210") {
		t.Errorf("expected 192.168.1.125 to match newline/semicolon delimited range")
	}

	// Test FindSegmentForIP
	foundSeg, err := testDB.FindSegmentForIP(net.ParseIP("192.168.1.150"))
	if err != nil || foundSeg == nil || foundSeg.ID != seg.ID {
		t.Errorf("expected foundSeg to match seg.ID, got %+v, err=%v", foundSeg, err)
	}
}

func TestValidateDHCPRange(t *testing.T) {
	// 1. Valid cases
	validTests := []struct {
		rangeStr string
		cidr     string
	}{
		{"", "192.168.1.0/24"},
		{"100-200", "192.168.1.0/24"},
		{"100~200", "192.168.1.0/24"},
		{"100〜200", "192.168.1.0/24"},
		{"50-100, 150-200", "192.168.1.0/24"},
		{"50-100\n150-200;210-220", "192.168.1.0/24"},
		{"192.168.1.50-192.168.1.150", "192.168.1.0/24"},
		{"192.168.1.50-150", "192.168.1.0/24"}, // Prefix range (start full IP, end host number)
		{"10.0.0.10-10.0.0.50, 10.0.0.60-10.0.0.100", "10.0.0.0/24"},
		{"192.168.0.100-200, 192.168.1.150-200", "192.168.1.0/23"},                                 // /23 multi-range prefix format
		{"192.168.0.100-192.168.0.200, 192.168.1.150-192.168.1.200", "192.168.1.0/23"},             // /23 multi-range full IP format
	}

	for _, tc := range validTests {
		if err := ValidateDHCPRange(tc.rangeStr, tc.cidr); err != nil {
			t.Errorf("expected valid for range %q and cidr %q, got error: %v", tc.rangeStr, tc.cidr, err)
		}
	}

	// 2. Invalid cases
	invalidTests := []struct {
		rangeStr string
		cidr     string
		desc     string
	}{
		{"100", "192.168.1.0/24", "missing delimiter"},
		{"200-100", "192.168.1.0/24", "start > end"},
		{"0-100", "192.168.1.0/24", "host number 0 out of bounds"},
		{"100-300", "192.168.1.0/24", "host number 300 out of bounds"},
		{"abc-def", "192.168.1.0/24", "non-numeric"},
		{"192.168.1.200-192.168.1.100", "192.168.1.0/24", "full IP start > end"},
		{"192.168.1.200-100", "192.168.1.0/24", "prefix range start > end"},
		{"192.168.2.100-192.168.2.200", "192.168.1.0/24", "full IP outside CIDR"},
		{"192.168.2.100-200", "192.168.1.0/23", "prefix range outside /23 subnet"},
		{"100-200", "192.168.1.0/28", "octet outside narrow subnet (/28)"},
		{"100-192.168.1.200", "192.168.1.0/24", "mismatched types"},
	}

	for _, tc := range invalidTests {
		if err := ValidateDHCPRange(tc.rangeStr, tc.cidr); err == nil {
			t.Errorf("expected error for %s (%q with %q), but got nil", tc.desc, tc.rangeStr, tc.cidr)
		}
	}
}

func TestHostPortScanSchedule(t *testing.T) {
	db := setupTestDB(t)

	h1 := &Host{IP: "192.168.1.10", Status: "up", Hostname: "active-host"}
	_, _, err := db.UpsertHostOnScan(h1)
	if err != nil {
		t.Fatalf("UpsertHostOnScan failed: %v", err)
	}

	// 1. Initially, next_port_scan is NULL so GetDuePortScanHost should return it
	dueHost, err := db.GetDuePortScanHost()
	if err != nil {
		t.Fatalf("GetDuePortScanHost failed: %v", err)
	}
	if dueHost == nil || dueHost.IP != "192.168.1.10" {
		t.Fatalf("expected 192.168.1.10 to be due, got %v", dueHost)
	}

	// 2. Schedule next scan with jitter (20-28h in future)
	nextScan := CalculateNextPortScanWithJitter(time.Now())
	if nextScan.Before(time.Now().Add(19 * time.Hour)) || nextScan.After(time.Now().Add(29 * time.Hour)) {
		t.Errorf("unexpected jitter range: %v", nextScan)
	}

	err = db.UpdateHostPortScanSchedule("192.168.1.10", "22:SSH,5900:VNC", nextScan)
	if err != nil {
		t.Fatalf("UpdateHostPortScanSchedule failed: %v", err)
	}

	// 3. Now it should NOT be due
	dueHostAfter, err := db.GetDuePortScanHost()
	if err != nil {
		t.Fatalf("GetDuePortScanHost after schedule failed: %v", err)
	}
	if dueHostAfter != nil {
		t.Errorf("expected no due hosts, but got: %v", dueHostAfter.IP)
	}

	// 4. Verify retrieved host has open ports and dates
	hFetched, err := db.GetHost("192.168.1.10")
	if err != nil || hFetched == nil {
		t.Fatalf("GetHost failed: %v", err)
	}
	if hFetched.OpenPorts != "22:SSH,5900:VNC" {
		t.Errorf("unexpected open ports: %s", hFetched.OpenPorts)
	}
	if hFetched.LastPortScan == nil || hFetched.NextPortScan == nil {
		t.Errorf("expected non-nil last_port_scan and next_port_scan")
	}
}

func TestSecurityRiskBadges(t *testing.T) {
	h := &Host{
		IP:        "192.168.1.20",
		OpenPorts: "80:HTTP,445:SMB,3389:RDP,5555:SoftEther VPN",
	}

	if !h.HasSecurityRisk() {
		t.Errorf("expected host with RDP and SoftEther to have security risks")
	}

	badges := h.SecurityRiskBadges()
	if len(badges) != 2 {
		t.Fatalf("expected 2 risk badges (RDP and VPN), got %d", len(badges))
	}

	hasVPN := false
	hasRDP := false
	for _, b := range badges {
		if b.Port == 5555 && b.Level == "critical" {
			hasVPN = true
		}
		if b.Port == 3389 && b.Level == "warning" {
			hasRDP = true
		}
	}

	if !hasVPN || !hasRDP {
		t.Errorf("missing expected badges: hasVPN=%v, hasRDP=%v", hasVPN, hasRDP)
	}

	// Host with SSH and Web should NOT be flagged as security risk
	devHost := &Host{
		IP:        "192.168.1.30",
		OpenPorts: "22:SSH,80:HTTP,3000:Node/Dev,389:LDAP",
	}
	if devHost.HasSecurityRisk() {
		t.Errorf("host with SSH, Web, Dev, and LDAP should not have security risks, but got %v", devHost.SecurityRiskBadges())
	}
	if !devHost.HasServiceInfo() {
		t.Errorf("host with SSH/Web/Dev/LDAP should have service info badges")
	}
	infoBadges := devHost.ServiceInfoBadges()
	if len(infoBadges) < 4 {
		t.Errorf("expected at least 4 info badges (SSH, Web, Dev, LDAP), got %d", len(infoBadges))
	}

	// Host with Telnet SHOULD be flagged as warning security risk
	// Host with Telnet SHOULD be flagged as warning security risk
	telnetHost := &Host{
		IP:        "192.168.1.40",
		OpenPorts: "23:Telnet",
	}
	if !telnetHost.HasSecurityRisk() {
		t.Errorf("host with Telnet should have security risk")
	}
	telnetBadges := telnetHost.SecurityRiskBadges()
	if len(telnetBadges) != 1 || telnetBadges[0].Port != 23 {
		t.Errorf("expected 1 telnet risk badge, got %v", telnetBadges)
	}

	// Host with TeamViewer (5938) and AnyDesk (7070) should have CRITICAL badges
	remoteHost := &Host{
		IP:        "192.168.1.50",
		OpenPorts: "5938:TeamViewer,7070:AnyDesk",
	}
	remoteBadges := remoteHost.SecurityRiskBadges()
	if len(remoteBadges) != 2 {
		t.Fatalf("expected 2 badges for TeamViewer and AnyDesk, got %d", len(remoteBadges))
	}
	for _, b := range remoteBadges {
		if b.Level != "critical" {
			t.Errorf("expected critical level for port %d (%s), got %s", b.Port, b.Service, b.Level)
		}
	}

	// Test port suppression
	remoteHost.IgnoredPorts = "7070"
	if !remoteHost.IsPortIgnored(7070) {
		t.Errorf("expected port 7070 to be ignored")
	}
	if remoteHost.IsPortIgnored(5938) {
		t.Errorf("expected port 5938 not to be ignored")
	}

	// Now SecurityRiskBadges should only contain TeamViewer (5938)
	filteredBadges := remoteHost.SecurityRiskBadges()
	if len(filteredBadges) != 1 || filteredBadges[0].Port != 5938 {
		t.Errorf("expected only TeamViewer risk badge, got %v", filteredBadges)
	}

	// SuppressedRiskBadges should contain AnyDesk (7070)
	suppressedBadges := remoteHost.SuppressedRiskBadges()
	if len(suppressedBadges) != 1 || suppressedBadges[0].Port != 7070 {
		t.Errorf("expected 1 suppressed badge for AnyDesk 7070, got %v", suppressedBadges)
	}
}

func TestTogglePortIgnored(t *testing.T) {
	db := setupTestDB(t)

	host := &Host{
		IP:        "192.168.1.60",
		Status:    "up",
		OpenPorts: "7070:AnyDesk",
	}
	_, _, err := db.UpsertHostOnScan(host)
	if err != nil {
		t.Fatalf("UpsertHostOnScan failed: %v", err)
	}

	// Verify initially it has risk
	h1, _ := db.GetHost("192.168.1.60")
	if !h1.HasSecurityRisk() {
		t.Fatalf("expected initial host to have security risk")
	}

	// Toggle ignore for 7070
	if err := db.TogglePortIgnored("192.168.1.60", 7070); err != nil {
		t.Fatalf("TogglePortIgnored failed: %v", err)
	}

	// Now it should NOT have risk
	h2, _ := db.GetHost("192.168.1.60")
	if h2.HasSecurityRisk() {
		t.Errorf("expected suppressed host to not have security risk")
	}
	if !h2.HasSuppressedRisks() {
		t.Errorf("expected host to have suppressed risk badges")
	}

	// Toggle again to unsuppress
	if err := db.TogglePortIgnored("192.168.1.60", 7070); err != nil {
		t.Fatalf("TogglePortIgnored unsuppress failed: %v", err)
	}
	h3, _ := db.GetHost("192.168.1.60")
	if !h3.HasSecurityRisk() {
		t.Errorf("expected unsuppressed host to have security risk again")
	}
}

func TestCustomPortsOperations(t *testing.T) {
	db := setupTestDB(t)

	// 1. Check seeded default ports
	allPorts, err := db.ListCustomPorts("")
	if err != nil {
		t.Fatalf("ListCustomPorts failed: %v", err)
	}
	if len(allPorts) != len(BuiltinDefaultPorts) {
		t.Fatalf("expected %d default ports, got %d", len(BuiltinDefaultPorts), len(allPorts))
	}

	// 2. Filter by profile
	macPorts, err := db.ListCustomPorts("apple_mac")
	if err != nil {
		t.Fatalf("ListCustomPorts(apple_mac) failed: %v", err)
	}
	if len(macPorts) == 0 {
		t.Errorf("expected apple_mac ports, got 0")
	}
	for _, p := range macPorts {
		if p.ProfileID != "apple_mac" {
			t.Errorf("expected profile apple_mac, got %s", p.ProfileID)
		}
	}

	// 3. Create a custom port
	newPort := &CustomPort{
		ProfileID:    "apple_mac",
		Protocol:     "TCP",
		Port:         8088,
		ProtocolName: "Custom App",
		Description:  "Internal test app",
		IsEnabled:    true,
	}
	if err := db.CreateCustomPort(newPort); err != nil {
		t.Fatalf("CreateCustomPort failed: %v", err)
	}
	if newPort.ID == 0 {
		t.Errorf("expected ID to be set")
	}

	// 4. Get the custom port
	fetched, err := db.GetCustomPort(newPort.ID)
	if err != nil {
		t.Fatalf("GetCustomPort failed: %v", err)
	}
	if fetched.Port != 8088 || fetched.ProtocolName != "Custom App" || !fetched.IsEnabled {
		t.Errorf("unexpected fetched custom port: %+v", fetched)
	}

	// 5. Update custom port
	if err := db.UpdateCustomPort(newPort.ID, "all", "TCP", 8088, "Global App", "Updated desc", "warning", true); err != nil {
		t.Fatalf("UpdateCustomPort failed: %v", err)
	}
	updated, _ := db.GetCustomPort(newPort.ID)
	if updated.ProfileID != "all" || updated.ProtocolName != "Global App" || updated.Severity != "warning" {
		t.Errorf("update failed, got: %+v", updated)
	}

	// 6. Toggle custom port
	newStatus, err := db.ToggleCustomPort(newPort.ID)
	if err != nil {
		t.Fatalf("ToggleCustomPort failed: %v", err)
	}
	if newStatus != false {
		t.Errorf("expected toggled status false, got %v", newStatus)
	}

	// 7. GetActiveTargetPortsForProfile
	// Since newPort is currently disabled, 8088 shouldn't be present
	activeWindows, err := db.GetActiveTargetPortsForProfile("windows")
	if err != nil {
		t.Fatalf("GetActiveTargetPortsForProfile failed: %v", err)
	}
	if _, ok := activeWindows[8088]; ok {
		t.Errorf("expected disabled 8088 to not be in active ports")
	}
	// Re-enable it
	_, _ = db.ToggleCustomPort(newPort.ID)
	activeWindows2, err := db.GetActiveTargetPortsForProfile("windows")
	if err != nil {
		t.Fatalf("GetActiveTargetPortsForProfile failed: %v", err)
	}
	if name, ok := activeWindows2[8088]; !ok || name != "Global App" {
		t.Errorf("expected enabled 8088 (profile=all) to be in windows active ports, got %s (exists=%v)", name, ok)
	}

	// 8. Delete custom port
	if err := db.DeleteCustomPort(newPort.ID); err != nil {
		t.Fatalf("DeleteCustomPort failed: %v", err)
	}
	_, err = db.GetCustomPort(newPort.ID)
	if err == nil {
		t.Errorf("expected error getting deleted custom port, got nil")
	}

	// 9. Export CSV
	csvStr, err := db.ExportCustomPortsCSV()
	if err != nil {
		t.Fatalf("ExportCustomPortsCSV failed: %v", err)
	}
	if len(csvStr) == 0 {
		t.Errorf("exported CSV is empty")
	}

	// 10. Import CSV (merge mode)
	csvData := `TargetOS,Protocol,Port,ProtocolName,Description,Enabled
windows,TCP,9999,TestPort,Test Description,true
`
	count, err := db.ImportCustomPortsCSV(csvData, false)
	if err != nil {
		t.Fatalf("ImportCustomPortsCSV merge failed: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 imported port, got %d", count)
	}
	winPorts, _ := db.ListCustomPorts("windows")
	found9999 := false
	for _, p := range winPorts {
		if p.Port == 9999 && p.ProtocolName == "TestPort" {
			found9999 = true
			break
		}
	}
	if !found9999 {
		t.Errorf("expected imported port 9999 to be present in windows profile")
	}

	// 11. Import CSV (replace mode)
	csvReplaceData := `TargetOS,Protocol,Port,ProtocolName,Description,Enabled
generic,TCP,12345,OnlyOne,Only port,true
`
	count, err = db.ImportCustomPortsCSV(csvReplaceData, true)
	if err != nil {
		t.Fatalf("ImportCustomPortsCSV replace failed: %v", err)
	}
	if count != 1 {
		t.Errorf("expected 1 imported port, got %d", count)
	}
	allAfterReplace, _ := db.ListCustomPorts("")
	if len(allAfterReplace) != 1 || allAfterReplace[0].Port != 12345 {
		t.Errorf("expected only 1 port after replace, got %d", len(allAfterReplace))
	}

	// 12. Reset to default
	if err := db.ResetCustomPortsToDefault(); err != nil {
		t.Fatalf("ResetCustomPortsToDefault failed: %v", err)
	}
	restoredPorts, _ := db.ListCustomPorts("")
	if len(restoredPorts) != len(BuiltinDefaultPorts) {
		t.Errorf("expected restored ports %d, got %d", len(BuiltinDefaultPorts), len(restoredPorts))
	}
}

