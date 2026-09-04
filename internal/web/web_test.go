package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lanmap/internal/config"
	"lanmap/internal/db"
	"lanmap/internal/notifier"
	"lanmap/internal/scanner"
)

func setupTestWeb(t *testing.T) (*Handler, http.Handler, *db.DB) {
	t.Helper()
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_web.db")
	database, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("Open DB failed: %v", err)
	}
	t.Cleanup(func() { database.Close() })

	cfg := &config.Config{
		HTTPPort:        3002,
		ScanConcurrency: 5,
	}

	sc := scanner.NewScanner(database, cfg)
	notif := notifier.NewNotifier(database)

	h, err := NewHandler(database, cfg, sc, notif)
	if err != nil {
		t.Fatalf("NewHandler failed: %v", err)
	}

	router := NewRouter(h)
	return h, router, database
}

func TestWebRoutes(t *testing.T) {
	_, router, database := setupTestWeb(t)

	// Create test segment & host
	seg, _ := database.CreateSegment("HQ LAN", "192.168.1.0/24", "eth0", true)
	_ = database.CreateManualHost(&db.Host{
		IP:          "192.168.1.50",
		SegmentID:   &seg.ID,
		DisplayName: "Test Workstation",
		Hostname:    "pc-01",
		IsApproved:  false,
	})

	// 1. Test Static file
	req := httptest.NewRequest("GET", "/static/htmx.min.js", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for /static/htmx.min.js, got %d", rec.Code)
	}

	// 2. Test Main Index
	req = httptest.NewRequest("GET", "/", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "lanmap") {
		t.Errorf("expected 200 and 'lanmap' in index, got %d", rec.Code)
	}

	// 3. Test Sidebar Partial
	req = httptest.NewRequest("GET", "/partials/sidebar", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "HQ LAN") {
		t.Errorf("expected 200 and 'HQ LAN' in sidebar, got %d", rec.Code)
	}

	// 4. Test Main Table Partial
	req = httptest.NewRequest("GET", "/partials/main_table", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "192.168.1.50") {
		t.Errorf("expected 200 and host IP in table, got %d", rec.Code)
	}

	// 5. Test Host Approval Toggle
	req = httptest.NewRequest("POST", "/api/hosts/192.168.1.50/toggle_approval", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 on toggle approval, got %d", rec.Code)
	}

	h, _ := database.GetHost("192.168.1.50")
	if !h.IsApproved {
		t.Errorf("expected host to be approved, got %+v", h)
	}

	// 6. Test Settings Modal & Update
	req = httptest.NewRequest("GET", "/modals/settings", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Retention Policy") {
		t.Errorf("expected 200 in settings modal, got %d", rec.Code)
	}

	form := url.Values{}
	form.Set("retention_days", "90")
	form.Set("webhook_slack_url", "https://hooks.slack.com/services/test")
	req = httptest.NewRequest("POST", "/api/settings", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 saving settings, got %d", rec.Code)
	}

	ret, _ := database.GetRetentionDays()
	if ret != 90 {
		t.Errorf("expected retention days updated to 90, got %d", ret)
	}

	// 7. Test Check Update endpoint
	req = httptest.NewRequest("GET", "/api/system/update/check", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 from update check, got %d", rec.Code)
	}

	// 8. Test Host Detail Modal endpoint (Default English)
	req = httptest.NewRequest("GET", "/modals/host_detail?ip=192.168.1.50", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Past 7-Day Ping Response Trends") {
		t.Errorf("expected 200 with 7-day ping metrics from host detail modal (English default), got %d body=%s", rec.Code, rec.Body.String())
	}

	// 8b. Test Host Detail Modal endpoint with Japanese Accept-Language
	reqJA := httptest.NewRequest("GET", "/modals/host_detail?ip=192.168.1.50", nil)
	reqJA.Header.Set("Accept-Language", "ja-JP,ja;q=0.9,en;q=0.8")
	recJA := httptest.NewRecorder()
	router.ServeHTTP(recJA, reqJA)
	if recJA.Code != http.StatusOK || !strings.Contains(recJA.Body.String(), "過去7日間の Ping レスポンス推移") {
		t.Errorf("expected 200 with 7-day ping metrics in Japanese, got %d", recJA.Code)
	}

	// 9. Test On-demand Ping Test endpoint
	req = httptest.NewRequest("POST", "/api/hosts/192.168.1.50/ping_test", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 from ping test endpoint, got %d", rec.Code)
	}

	// 9b. Test On-demand Probe Ports endpoint
	req = httptest.NewRequest("POST", "/api/hosts/192.168.1.50/probe_ports", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "modal-ports-container") {
		t.Errorf("expected 200 and modal-ports-container from probe ports endpoint, got %d body=%s", rec.Code, rec.Body.String())
	}

	// 10. Test Favicon endpoints (/favicon.ico and /static/favicon.svg)
	req = httptest.NewRequest("GET", "/favicon.ico", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 from /favicon.ico, got %d", rec.Code)
	}

	req = httptest.NewRequest("GET", "/static/favicon.svg", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 from /static/favicon.svg, got %d", rec.Code)
	}

	// 11. Test Segment Menu & Toggle (Default English)
	req = httptest.NewRequest("GET", fmt.Sprintf("/partials/segment_menu?id=%d", seg.ID), nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Scanning") {
		t.Errorf("expected 200 and 'Scanning' in segment menu, got %d body=%s", rec.Code, rec.Body.String())
	}

	req = httptest.NewRequest("POST", fmt.Sprintf("/api/segments/%d/toggle", seg.ID), nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 from toggle segment, got %d", rec.Code)
	}

	segUpdated, _ := database.GetSegment(seg.ID)
	if segUpdated.IsEnabled {
		t.Errorf("expected segment to be toggled to disabled, got %+v", segUpdated)
	}

	// 12. Test Segment Modal with Unadded Networks suggestion (Default English & Japanese)
	req = httptest.NewRequest("GET", "/modals/segment", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Add Network Segment") {
		t.Errorf("expected 200 and 'Add Network Segment' from /modals/segment, got %d", rec.Code)
	}

	reqSegJA := httptest.NewRequest("GET", "/modals/segment", nil)
	reqSegJA.Header.Set("Accept-Language", "ja")
	recSegJA := httptest.NewRecorder()
	router.ServeHTTP(recSegJA, reqSegJA)
	if recSegJA.Code != http.StatusOK || !strings.Contains(recSegJA.Body.String(), "ネットワークセグメントの追加") {
		t.Errorf("expected 200 and 'ネットワークセグメントの追加' from /modals/segment in Japanese, got %d", recSegJA.Code)
	}

	// 13. Test DHCP Range in Segment & Main Table Rendering
	seg.DHCPRange = "100-200"
	_ = database.UpdateSegment(seg)
	_ = database.CreateManualHost(&db.Host{
		IP:          "192.168.1.150",
		SegmentID:   &seg.ID,
		DisplayName: "DHCP Mobile Phone",
		Hostname:    "iphone-taro",
		IsApproved:  false,
	})

	req = httptest.NewRequest("GET", "/partials/main_table", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "DHCP") {
		t.Errorf("expected 200 and 'DHCP' in main table, got %d", rec.Code)
	}

	// 14. Test Toggle Host DHCP via API and Action Menu
	req = httptest.NewRequest("POST", "/api/hosts/192.168.1.150/toggle_dhcp", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 from /api/hosts/192.168.1.150/toggle_dhcp, got %d", rec.Code)
	}

	h150, _ := database.GetHost("192.168.1.150")
	if !h150.IsDHCP {
		t.Errorf("expected h150 IsDHCP to be toggled to true")
	}

	// Test Action Menu contains DHCP option
	req = httptest.NewRequest("GET", "/partials/action_menu?ip=192.168.1.150", nil)
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "toggle_dhcp") {
		t.Errorf("expected action menu to contain toggle_dhcp, got %s", rec.Body.String())
	}

	// 15. Test Segment DHCP Range Validation on POST
	// A. Invalid range should return 422 Unprocessable Entity with error container
	valForm := strings.NewReader("name=TestLAN&cidr=192.168.1.0/24&dhcp_range=200-100&is_enabled=true")
	req = httptest.NewRequest("POST", "/api/segments", valForm)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "開始ホスト番号") {
		t.Errorf("expected 422 and validation error message, got status=%d body=%s", rec.Code, rec.Body.String())
	}

	// B. Range outside CIDR should return 422 Unprocessable Entity
	valForm = strings.NewReader("name=TestLAN&cidr=192.168.1.0/24&dhcp_range=192.168.2.100-192.168.2.200&is_enabled=true")
	req = httptest.NewRequest("POST", "/api/segments", valForm)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnprocessableEntity || !strings.Contains(rec.Body.String(), "含まれていません") {
		t.Errorf("expected 422 and subnet error, got status=%d body=%s", rec.Code, rec.Body.String())
	}

	// C. Valid /23 multi-range prefix format (e.g. 192.168.0.100-200, 192.168.1.150-200 in 192.168.1.0/23)
	valForm = strings.NewReader("name=BranchLAN&cidr=192.168.1.0/23&dhcp_range=192.168.0.100-200,192.168.1.150-200&is_enabled=true")
	req = httptest.NewRequest("POST", "/api/segments", valForm)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for valid /23 multi-range prefix DHCP, got status=%d body=%s", rec.Code, rec.Body.String())
	}

	// D. Valid range should succeed with 200 OK
	valForm = strings.NewReader("name=TestLAN&cidr=192.168.1.0/24&dhcp_range=100-150,180-200&is_enabled=true&is_dhcp_manual=true")
	req = httptest.NewRequest("POST", "/api/segments", valForm)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 for valid DHCP range, got status=%d body=%s", rec.Code, rec.Body.String())
	}

	// 16. Test Language Switching Endpoint and Cookie Detection
	// A. Set language to JA
	reqLang := httptest.NewRequest("POST", "/api/set_language?lang=ja", nil)
	recLang := httptest.NewRecorder()
	router.ServeHTTP(recLang, reqLang)
	if recLang.Code != http.StatusOK {
		t.Errorf("expected 200 from /api/set_language, got %d", recLang.Code)
	}
	if recLang.Header().Get("HX-Refresh") != "true" {
		t.Errorf("expected HX-Refresh: true from /api/set_language")
	}
	cookieHeader := recLang.Header().Get("Set-Cookie")
	if !strings.Contains(cookieHeader, "lanmap_lang=ja") {
		t.Errorf("expected lanmap_lang=ja in Set-Cookie, got: %s", cookieHeader)
	}

	// B. Test that cookie overrides Accept-Language
	reqCookie := httptest.NewRequest("GET", "/modals/segment", nil)
	reqCookie.AddCookie(&http.Cookie{Name: "lanmap_lang", Value: "ja"})
	reqCookie.Header.Set("Accept-Language", "en-US,en;q=0.9") // Browser header is English, but cookie is ja
	recCookie := httptest.NewRecorder()
	router.ServeHTTP(recCookie, reqCookie)
	if recCookie.Code != http.StatusOK || !strings.Contains(recCookie.Body.String(), "ネットワークセグメントの追加") {
		t.Errorf("expected Japanese output due to lanmap_lang=ja cookie, got body=%s", recCookie.Body.String())
	}

	// 17. Test Port Suppression Endpoint & Host Update with Ignored Ports
	_ = database.CreateManualHost(&db.Host{
		IP:        "192.168.1.99",
		Status:    "up",
		OpenPorts: "7070:AnyDesk,5938:TeamViewer",
	})

	// Toggle suppression for 7070
	reqSupp := httptest.NewRequest("POST", "/api/hosts/192.168.1.99/toggle_port_suppress?port=7070", nil)
	recSupp := httptest.NewRecorder()
	router.ServeHTTP(recSupp, reqSupp)
	if recSupp.Code != http.StatusOK {
		t.Errorf("expected 200 from /api/hosts/192.168.1.99/toggle_port_suppress, got %d", recSupp.Code)
	}
	if recSupp.Header().Get("HX-Trigger") != "refreshMainTable" {
		t.Errorf("expected HX-Trigger: refreshMainTable, got: %s", recSupp.Header().Get("HX-Trigger"))
	}

	hSupp, _ := database.GetHost("192.168.1.99")
	if !hSupp.IsPortIgnored(7070) {
		t.Errorf("expected port 7070 to be ignored on host, got %s", hSupp.IgnoredPorts)
	}

	// Update host manual with ignored_ports
	updateForm := strings.NewReader("display_name=JumpBox&is_static_ip=true&ignored_ports=7070,5938")
	reqUp := httptest.NewRequest("POST", "/api/hosts/192.168.1.99/update", updateForm)
	reqUp.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recUp := httptest.NewRecorder()
	router.ServeHTTP(recUp, reqUp)
	if recUp.Code != http.StatusOK {
		t.Errorf("expected 200 from host update, got %d", recUp.Code)
	}
	hUp, _ := database.GetHost("192.168.1.99")
	if hUp.IgnoredPorts != "7070,5938" {
		t.Errorf("expected ignored_ports to be '7070,5938', got '%s'", hUp.IgnoredPorts)
	}
	if hUp.HasSecurityRisk() {
		t.Errorf("both 7070 and 5938 are suppressed, host should not have security risk")
	}
}

func TestWebFiltersAndPreviousHost(t *testing.T) {
	_, router, database := setupTestWeb(t)

	now := time.Now()
	// Create segment
	seg, err := database.CreateSegment("Office", "10.0.0.0/24", "eth0", true)
	if err != nil {
		t.Fatalf("CreateSegment: %v", err)
	}

	// 1. Insert an active DHCP host
	_, _, err = database.UpsertHostOnScan(&db.Host{
		IP:          "10.0.0.20",
		MACAddress: "aa:bb:cc:11:22:33",
		Hostname:   "pc-alice",
		DisplayName: "Alice PC",
		SegmentID:   &seg.ID,
		IsDHCP:      true,
		Status:      "up",
	})
	if err != nil {
		t.Fatalf("UpsertHostOnScan: %v", err)
	}

	// Verify it shows up as UP with 🔵 in table
	req := httptest.NewRequest("GET", "/partials/main_table?filter=online", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "10.0.0.20") || !strings.Contains(body, "🔵") {
		t.Errorf("expected 10.0.0.20 with 🔵 in online view, got body:\n%s", body)
	}

	// 2. Now a new host (different MAC) arrives on the same IP 10.0.0.20
	_, _, err = database.UpsertHostOnScan(&db.Host{
		IP:          "10.0.0.20",
		MACAddress: "aa:bb:cc:44:55:66",
		Hostname:   "pc-bob",
		DisplayName: "Bob PC",
		SegmentID:   &seg.ID,
		IsDHCP:      true,
		Status:      "up",
	})
	if err != nil {
		t.Fatalf("UpsertHostOnScan Bob: %v", err)
	}

	// Get the two hosts from DB
	hostAlice, err := database.GetHostByMAC("aa:bb:cc:11:22:33")
	if err != nil {
		t.Fatalf("GetHostByMAC Alice: %v", err)
	}
	hostBob, err := database.GetHostByMAC("aa:bb:cc:44:55:66")
	if err != nil {
		t.Fatalf("GetHostByMAC Bob: %v", err)
	}

	if hostAlice.Status != "down" {
		t.Errorf("expected Alice to be down, got %s", hostAlice.Status)
	}
	if hostBob.Status != "up" {
		t.Errorf("expected Bob to be up, got %s", hostBob.Status)
	}

	// In online view, only Bob should appear
	reqOnline := httptest.NewRequest("GET", "/partials/main_table?filter=online", nil)
	recOnline := httptest.NewRecorder()
	router.ServeHTTP(recOnline, reqOnline)
	bodyOnline := recOnline.Body.String()
	if !strings.Contains(bodyOnline, "aa:bb:cc:44:55:66") {
		t.Errorf("expected Bob in online view")
	}
	if strings.Contains(bodyOnline, "aa:bb:cc:11:22:33") {
		t.Errorf("did not expect Alice in online view")
	}

	// In 3d view (default), BOTH should appear! Alice should have ⚪ and previous host badge
	req3d := httptest.NewRequest("GET", "/partials/main_table?filter=3d", nil)
	rec3d := httptest.NewRecorder()
	router.ServeHTTP(rec3d, req3d)
	body3d := rec3d.Body.String()
	if !strings.Contains(body3d, "aa:bb:cc:44:55:66") || !strings.Contains(body3d, "aa:bb:cc:11:22:33") {
		t.Errorf("expected both Bob and Alice in 3d view")
	}
	if !strings.Contains(body3d, "⚪") {
		t.Errorf("expected ⚪ for offline Alice in 3d view")
	}
	if !strings.Contains(body3d, "前回") && !strings.Contains(body3d, "Prev") {
		t.Errorf("expected previous host badge in 3d view")
	}

	// 3. Test ID-based actions on Alice specifically
	// Alice is currently unapproved. Toggle approval for Alice by ID.
	reqApproveAlice := httptest.NewRequest("POST", fmt.Sprintf("/api/hosts/10.0.0.20/toggle_approval?id=%d", hostAlice.ID), nil)
	recApproveAlice := httptest.NewRecorder()
	router.ServeHTTP(recApproveAlice, reqApproveAlice)
	if recApproveAlice.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", recApproveAlice.Code)
	}

	aliceReloaded, _ := database.GetHostByID(hostAlice.ID)
	bobReloaded, _ := database.GetHostByID(hostBob.ID)
	if !aliceReloaded.IsApproved {
		t.Errorf("expected Alice to be approved via ID action")
	}
	if bobReloaded.IsApproved {
		t.Errorf("expected Bob to remain unapproved")
	}

	// Test ID-based delete on Alice
	reqDelAlice := httptest.NewRequest("DELETE", fmt.Sprintf("/api/hosts/10.0.0.20?id=%d", hostAlice.ID), nil)
	recDelAlice := httptest.NewRecorder()
	router.ServeHTTP(recDelAlice, reqDelAlice)
	if recDelAlice.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", recDelAlice.Code)
	}

	aliceAfterDel, _ := database.GetHostByID(hostAlice.ID)
	if aliceAfterDel != nil {
		t.Errorf("expected Alice to be deleted")
	}
	bobAfterDel, _ := database.GetHostByID(hostBob.ID)
	if bobAfterDel == nil {
		t.Errorf("expected Bob to still exist after Alice deleted")
	}

	// 4. Test Days limit filtering (3d vs 7d vs all)
	// Insert host Charlie seen 5 days ago (should not appear in 3d, but should appear in 7d and all)
	seen5dAgo := now.Add(-5 * 24 * time.Hour)
	charlie := &db.Host{
		IP:         "10.0.0.30",
		MACAddress: "CC:CC:CC:33:33:33",
		Status:     "down",
		FirstSeen:  seen5dAgo,
		LastSeen:   &seen5dAgo,
	}
	_ = database.CreateManualHost(charlie)
	// Update last_seen to 5 days ago explicitly
	_, _ = database.Exec("UPDATE hosts SET last_seen = ? WHERE ip = '10.0.0.30'", seen5dAgo)

	// Charlie in 3d: should NOT appear
	reqCheck3d := httptest.NewRequest("GET", "/partials/main_table?filter=3d", nil)
	recCheck3d := httptest.NewRecorder()
	router.ServeHTTP(recCheck3d, reqCheck3d)
	if strings.Contains(recCheck3d.Body.String(), "10.0.0.30") {
		t.Errorf("host from 5 days ago should NOT appear in 3d filter")
	}

	// Charlie in 7d: SHOULD appear
	reqCheck7d := httptest.NewRequest("GET", "/partials/main_table?filter=7d", nil)
	recCheck7d := httptest.NewRecorder()
	router.ServeHTTP(recCheck7d, reqCheck7d)
	if !strings.Contains(recCheck7d.Body.String(), "10.0.0.30") {
		t.Errorf("host from 5 days ago SHOULD appear in 7d filter")
	}
}

func TestCustomPortsWebRoutes(t *testing.T) {
	_, router, database := setupTestWeb(t)

	// 1. GET /partials/custom_ports
	req := httptest.NewRequest("GET", "/partials/custom_ports?profile=all_profiles", nil)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 for /partials/custom_ports, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "TeamViewer") || !strings.Contains(body, "5938") {
		t.Errorf("expected TeamViewer / 5938 in custom_ports table")
	}

	// 2. GET /modals/custom_port (add new)
	reqAdd := httptest.NewRequest("GET", "/modals/custom_port", nil)
	recAdd := httptest.NewRecorder()
	router.ServeHTTP(recAdd, reqAdd)
	if recAdd.Code != http.StatusOK {
		t.Errorf("expected 200 for /modals/custom_port, got %d", recAdd.Code)
	}

	// 3. POST /api/ports (create)
	form := url.Values{
		"profile_id":    {"apple_mac"},
		"protocol":      {"TCP"},
		"port":          {"9090"},
		"protocol_name": {"Test App"},
		"description":   {"Test Description"},
		"is_enabled":    {"1"},
	}
	reqCreate := httptest.NewRequest("POST", "/api/ports", strings.NewReader(form.Encode()))
	reqCreate.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recCreate := httptest.NewRecorder()
	router.ServeHTTP(recCreate, reqCreate)
	if recCreate.Code != http.StatusOK {
		t.Fatalf("expected 200 for POST /api/ports, got %d", recCreate.Code)
	}
	if !strings.Contains(recCreate.Body.String(), "9090") || !strings.Contains(recCreate.Body.String(), "Test App") {
		t.Errorf("expected created port 9090 in response table")
	}

	// Fetch created port ID from DB
	macPorts, _ := database.ListCustomPorts("apple_mac")
	var targetPort *db.CustomPort
	for _, p := range macPorts {
		if p.Port == 9090 {
			targetPort = p
			break
		}
	}
	if targetPort == nil {
		t.Fatalf("created port 9090 not found in database")
	}

	// 4. GET /modals/custom_port?id=... (edit modal)
	reqEditModal := httptest.NewRequest("GET", fmt.Sprintf("/modals/custom_port?id=%d", targetPort.ID), nil)
	recEditModal := httptest.NewRecorder()
	router.ServeHTTP(recEditModal, reqEditModal)
	if recEditModal.Code != http.StatusOK {
		t.Errorf("expected 200 for edit modal, got %d", recEditModal.Code)
	}
	if !strings.Contains(recEditModal.Body.String(), "9090") {
		t.Errorf("expected edit modal to contain port 9090")
	}

	// 5. POST /api/ports/{id}/toggle
	reqToggle := httptest.NewRequest("POST", fmt.Sprintf("/api/ports/%d/toggle", targetPort.ID), nil)
	recToggle := httptest.NewRecorder()
	router.ServeHTTP(recToggle, reqToggle)
	if recToggle.Code != http.StatusOK {
		t.Fatalf("expected 200 for toggle, got %d", recToggle.Code)
	}
	pAfterToggle, _ := database.GetCustomPort(targetPort.ID)
	if pAfterToggle.IsEnabled {
		t.Errorf("expected port to be disabled after toggle")
	}

	// 6. POST /api/ports/{id}/update
	updateForm := url.Values{
		"profile_id":    {"windows"},
		"protocol":      {"TCP"},
		"port":          {"9091"},
		"protocol_name": {"Updated App"},
		"description":   {"Updated Description"},
		"is_enabled":    {"1"},
	}
	reqUpdate := httptest.NewRequest("POST", fmt.Sprintf("/api/ports/%d/update", targetPort.ID), strings.NewReader(updateForm.Encode()))
	reqUpdate.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recUpdate := httptest.NewRecorder()
	router.ServeHTTP(recUpdate, reqUpdate)
	if recUpdate.Code != http.StatusOK {
		t.Fatalf("expected 200 for update, got %d", recUpdate.Code)
	}
	pAfterUpdate, _ := database.GetCustomPort(targetPort.ID)
	if pAfterUpdate.Port != 9091 || pAfterUpdate.ProfileID != "windows" {
		t.Errorf("unexpected updated port: %+v", pAfterUpdate)
	}

	// 7. DELETE /api/ports/{id}
	reqDel := httptest.NewRequest("DELETE", fmt.Sprintf("/api/ports/%d", targetPort.ID), nil)
	recDel := httptest.NewRecorder()
	router.ServeHTTP(recDel, reqDel)
	if recDel.Code != http.StatusOK {
		t.Fatalf("expected 200 for delete, got %d", recDel.Code)
	}
	_, err := database.GetCustomPort(targetPort.ID)
	if err == nil {
		t.Errorf("expected deleted port to not exist in DB")
	}

	// 8. GET /api/ports/export
	reqExp := httptest.NewRequest("GET", "/api/ports/export", nil)
	recExp := httptest.NewRecorder()
	router.ServeHTTP(recExp, reqExp)
	if recExp.Code != http.StatusOK {
		t.Fatalf("expected 200 for CSV export, got %d", recExp.Code)
	}
	if !strings.Contains(recExp.Body.String(), "TargetOS,Protocol,Port") {
		t.Errorf("expected CSV header in export output")
	}

	// 9. GET /modals/custom_ports_import
	reqImpModal := httptest.NewRequest("GET", "/modals/custom_ports_import", nil)
	recImpModal := httptest.NewRecorder()
	router.ServeHTTP(recImpModal, reqImpModal)
	if recImpModal.Code != http.StatusOK {
		t.Errorf("expected 200 for CSV import modal, got %d", recImpModal.Code)
	}

	// 10. POST /api/ports/import
	impForm := url.Values{
		"csv_data": {"TargetOS,Protocol,Port,ProtocolName,Description,Enabled\napple_mac,TCP,18080,ImportedWeb,Imported Note,true\n"},
		"replace":  {"false"},
	}
	reqImp := httptest.NewRequest("POST", "/api/ports/import", strings.NewReader(impForm.Encode()))
	reqImp.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	recImp := httptest.NewRecorder()
	router.ServeHTTP(recImp, reqImp)
	if recImp.Code != http.StatusOK {
		t.Fatalf("expected 200 for import, got %d", recImp.Code)
	}
	if !strings.Contains(recImp.Body.String(), "18080") || !strings.Contains(recImp.Body.String(), "ImportedWeb") {
		t.Errorf("expected imported port 18080 in response table")
	}

	// 11. POST /api/ports/reset
	reqReset := httptest.NewRequest("POST", "/api/ports/reset", nil)
	recReset := httptest.NewRecorder()
	router.ServeHTTP(recReset, reqReset)
	if recReset.Code != http.StatusOK {
		t.Fatalf("expected 200 for reset, got %d", recReset.Code)
	}
	allAfterReset, _ := database.ListCustomPorts("")
	if len(allAfterReset) != len(db.BuiltinDefaultPorts) {
		t.Errorf("expected %d default ports after reset, got %d", len(db.BuiltinDefaultPorts), len(allAfterReset))
	}
}

