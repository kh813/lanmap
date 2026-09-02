package scanner

import (
	"context"
	"path/filepath"
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
		{"00:00:0C:11:22:33", "Cisco Systems"},
		{"00:11:32:44:55:66", "Synology"},
		{"B8:27:EB:00:11:22", "Raspberry Pi Foundation"},
		{"00:00:00:00:00:00", ""},
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
