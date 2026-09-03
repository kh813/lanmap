package scanner

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"lanmap/internal/config"
	"lanmap/internal/db"
)

func TestOUILookup(t *testing.T) {
	tests := []struct {
		mac      string
		expected string
	}{
		{"00:03:93:11:22:33", "Apple"},
		{"00-03-93-aa-bb-cc", "Apple"},
		{"000393aabbcc", "Apple"},
		{"00:00:0C:11:22:33", "Cisco"},
		{"00:11:32:44:55:66", "Synology"},
		{"B8:27:EB:00:11:22", "Raspberry Pi"},
		{"00:00:00:00:00:00", ""},
		{"8a:22:c1:5c:85:f7", "端末 (プライベートMAC / Wi-Fi匿名化)"},
		{"invalid", ""},
	}

	for _, tt := range tests {
		got := LookupVendor(tt.mac)
		if got != tt.expected {
			t.Errorf("LookupVendor(%s) = %q, expected %q", tt.mac, got, tt.expected)
		}
	}
}

func TestDetectOSByTTL(t *testing.T) {
	tests := []struct {
		ttl      int
		expected string
	}{
		{64, "Linux / macOS / iOS / Android"},
		{54, "Linux / macOS / iOS / Android"},
		{128, "Windows"},
		{110, "Windows"},
		{255, "Network Device / Cisco"},
		{0, ""},
	}

	for _, tt := range tests {
		got := DetectOSByTTL(tt.ttl)
		if got != tt.expected {
			t.Errorf("DetectOSByTTL(%d) = %q, expected %q", tt.ttl, got, tt.expected)
		}
	}
}

func TestGenerateIPs(t *testing.T) {
	ips, err := generateIPs("192.168.1.0/30")
	if err != nil {
		t.Fatalf("generateIPs failed: %v", err)
	}
	if len(ips) != 2 {
		t.Fatalf("expected 2 host IPs for /30, got %d", len(ips))
	}
	if ips[0].String() != "192.168.1.1" || ips[1].String() != "192.168.1.2" {
		t.Errorf("unexpected IPs: %v, %v", ips[0], ips[1])
	}
}

func TestNormalizeMAC(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"0:3:93:1:2:3", "00:03:93:01:02:03"},
		{"AA-BB-CC-DD-EE-FF", "aa:bb:cc:dd:ee:ff"},
		{"aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff"},
	}

	for _, tt := range tests {
		got := normalizeMAC(tt.input)
		if got != tt.expected {
			t.Errorf("normalizeMAC(%s) = %s, expected %s", tt.input, got, tt.expected)
		}
	}
}

func TestScannerWorkflowWithMock(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_scanner.db")
	database, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open failed: %v", err)
	}
	defer database.Close()

	cfg := &config.Config{
		ScanConcurrency: 5,
		ScanInterval:    10 * time.Minute,
	}

	seg, err := database.CreateSegment("Test LAN", "127.0.0.1/32", "lo0", true)
	if err != nil {
		t.Fatalf("CreateSegment failed: %v", err)
	}

	scanner := NewScanner(database, cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	reports, err := scanner.ScanSegment(ctx, seg)
	if err != nil {
		t.Fatalf("ScanSegment failed: %v", err)
	}

	t.Logf("Scan reports count: %d", len(reports))
	for _, r := range reports {
		t.Logf("Host detected: IP=%s, Status=%s", r.Host.IP, r.Host.Status)
	}
}

func TestScanOpenPorts(t *testing.T) {
	// Test on loopback with short timeout
	ports := ScanOpenPorts("127.0.0.1", 30*time.Millisecond)
	t.Logf("Local open ports: %s", ports)
}

func TestExtendedProbes(t *testing.T) {
	// 1. mDNS Model resolution
	model := ResolveMDNSModel("MacBookPro18,1", "mbpm1m.local")
	if model != "MacBook Pro (16-inch, 2021 M1 Pro)" {
		t.Errorf("unexpected model: %s", model)
	}

	model2 := ResolveMDNSModel("", "ipad-me1tb-m4.local")
	if model2 != "Apple iPad Pro (M4 1TB)" {
		t.Errorf("unexpected model2: %s", model2)
	}

	// 2. Jitter calculation
	j1 := RecordRTTAndCalculateJitter("10.0.0.1", 10.0)
	j2 := RecordRTTAndCalculateJitter("10.0.0.1", 12.0)
	j3 := RecordRTTAndCalculateJitter("10.0.0.1", 10.5)
	t.Logf("Jitter calculated: %v, %v, %v", j1, j2, j3)

	// 3. Web title and UPnP extraction safety
	_ = ExtractWebTitle("127.0.0.1", "80:HTTP")
	_ = FetchUPnPInfo("127.0.0.1")
	_ = InspectTLSCert("127.0.0.1")
}

func TestDetectDetailedOS(t *testing.T) {
	// 1. iPhone 16 Pro -> iOS 18
	os1 := DetectDetailedOS("192.168.3.150", "iphone16p.parkside.tokyo", "Apple", "iOS", "iPhone 16 Pro", "", "", "", "")
	if !strings.Contains(os1, "iOS 18") {
		t.Errorf("expected iOS 18, got %s", os1)
	}

	// 2. iPad Pro M4 -> iPadOS 18
	os2 := DetectDetailedOS("192.168.3.160", "ipad-me1tb-m4.parkside.tokyo", "Apple", "iOS", "", "", "", "", "")
	if !strings.Contains(os2, "iPadOS 18") {
		t.Errorf("expected iPadOS 18, got %s", os2)
	}

	// 3. MacBook Pro M1 -> macOS 15
	os3 := DetectDetailedOS("192.168.3.170", "mbpm1m.parkside.tokyo", "Apple", "macOS", "MacBookPro18,1", "", "", "", "")
	if !strings.Contains(os3, "macOS 15") {
		t.Errorf("expected macOS 15, got %s", os3)
	}

	// 4. OpenWrt Web Title
	os4 := DetectDetailedOS("192.168.3.1", "openwrt.lan", "", "Linux", "", "OpenWrt - LuCI 23.05", "80:HTTP", "", "")
	if !strings.Contains(os4, "OpenWrt 23.05") {
		t.Errorf("expected OpenWrt 23.05, got %s", os4)
	}
}
