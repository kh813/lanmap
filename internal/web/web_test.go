package web

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

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
	// A. Invalid range should return 400 Bad Request with error container
	valForm := strings.NewReader("name=TestLAN&cidr=192.168.1.0/24&dhcp_range=200-100&is_enabled=true")
	req = httptest.NewRequest("POST", "/api/segments", valForm)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "開始ホスト番号") {
		t.Errorf("expected 400 and validation error message, got status=%d body=%s", rec.Code, rec.Body.String())
	}

	// B. Range outside CIDR should return 400 Bad Request
	valForm = strings.NewReader("name=TestLAN&cidr=192.168.1.0/24&dhcp_range=192.168.2.100-192.168.2.200&is_enabled=true")
	req = httptest.NewRequest("POST", "/api/segments", valForm)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec = httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "含まれていません") {
		t.Errorf("expected 400 and subnet error, got status=%d body=%s", rec.Code, rec.Body.String())
	}

	// C. Valid range should succeed with 200 OK
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
}
