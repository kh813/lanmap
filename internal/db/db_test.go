package db

import (
	"net"
	"path/filepath"
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

	// Check retention days seed
	retDays, err := db.GetRetentionDays()
	if err != nil {
		t.Fatalf("GetRetentionDays failed: %v", err)
	}
	if retDays != 90 {
		t.Errorf("expected retention days 90, got %d", retDays)
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

	// 3. DHCP IP reuse with DIFFERENT MAC address (Section 4.2.1)
	h1DifferentMAC := &Host{
		IP:          "192.168.1.100",
		MACAddress:  "dd:ee:ff:44:55:66",
		Hostname:    "unknown-device",
		VendorModel: "Unknown Vendor",
	}
	isNew, isReplaced, err = db.UpsertHostOnScan(h1DifferentMAC)
	if err != nil {
		t.Fatalf("UpsertHostOnScan with different MAC failed: %v", err)
	}
	if isNew || !isReplaced {
		t.Errorf("expected isNew=false, isReplaced=true on MAC change, got isNew=%v, isReplaced=%v", isNew, isReplaced)
	}

	storedAfterReuse, err := db.GetHost(h1.IP)
	if err != nil || storedAfterReuse == nil {
		t.Fatalf("GetHost after reuse failed: %v", err)
	}
	if storedAfterReuse.IsApproved {
		t.Error("expected is_approved to be reset to false when MAC changed")
	}
	if storedAfterReuse.MACAddress != "dd:ee:ff:44:55:66" {
		t.Errorf("expected new MAC address, got %s", storedAfterReuse.MACAddress)
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

	// 2. Protected host -> should NOT be deleted
	insertOldHost("192.168.1.2", "22:22:22:22:22:22", true, false, false, false)

	// 3. Monitored host -> should NOT be deleted
	insertOldHost("192.168.1.3", "33:33:33:33:33:33", false, true, false, false)

	// 4. Static IP host -> should NOT be deleted
	insertOldHost("192.168.1.4", "44:44:44:44:44:44", false, false, true, false)

	// 5. Approved host -> should NOT be deleted
	insertOldHost("192.168.1.5", "55:55:55:55:55:55", false, false, false, true)

	// 6. Multiple flags (protected + approved) -> should NOT be deleted
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
	for _, ip := range []string{"192.168.1.2", "192.168.1.3", "192.168.1.4", "192.168.1.5", "192.168.1.6"} {
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

	// Test purge
	err = db.PurgeOldPingHistory(7)
	if err != nil {
		t.Fatalf("PurgeOldPingHistory failed: %v", err)
	}
}
