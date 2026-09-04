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
		{"bc:a5:11:e0:90:cf", "Netgear"},
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
	// 1. Evidence-based mDNS Model resolution
	model := ResolveMDNSModel("MacBookPro18,4")
	if model != "MacBook Pro (14-inch, 2021 M1 Max)" {
		t.Errorf("unexpected model: %s", model)
	}

	model2 := ResolveMDNSModel("iPad16,3")
	if model2 != "iPad Pro 11-inch (M4, 2024)" {
		t.Errorf("unexpected model2: %s", model2)
	}

	// Empty / no evidence returns empty string (no guessing!)
	modelEmpty := ResolveMDNSModel("")
	if modelEmpty != "" {
		t.Errorf("expected empty model for empty input, got %s", modelEmpty)
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
	// 1. Verified Model Signature MacBookPro18,4 -> macOS (Apple Silicon)
	os1 := DetectDetailedOS("192.168.3.170", "mbpm1m.parkside.tokyo", "Apple", "macOS", "MacBook Pro (14-inch, 2021 M1 Max)", "", "", "", "")
	if !strings.Contains(os1, "macOS (Apple Silicon)") {
		t.Errorf("expected macOS (Apple Silicon), got %s", os1)
	}

	// 2. Verified Model Signature iPhone17,1 -> iOS (Apple iPhone)
	os2 := DetectDetailedOS("192.168.3.150", "random-hostname.local", "Apple", "iOS", "iPhone 16 Pro", "", "", "", "")
	if !strings.Contains(os2, "iOS (Apple iPhone)") {
		t.Errorf("expected iOS (Apple iPhone), got %s", os2)
	}

	// 3. OpenWrt Web Title
	os3 := DetectDetailedOS("192.168.3.1", "custom-router.lan", "", "Linux", "", "OpenWrt - LuCI 23.05", "80:HTTP", "", "")
	if !strings.Contains(os3, "OpenWrt 23.05") {
		t.Errorf("expected OpenWrt 23.05, got %s", os3)
	}

	// 4. Netgear Network Equipment
	os4 := DetectDetailedOS("192.168.3.9", "", "Netgear", "Linux", "", "", "80:HTTP,443:HTTPS", "", "")
	if !strings.Contains(os4, "Netgear Firmware") {
		t.Errorf("expected Netgear Firmware, got %s", os4)
	}
}

func TestEnsureLocalSegmentDefaultGateway(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_seg_gw.db")
	database, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("Open DB failed: %v", err)
	}
	defer database.Close()

	cfg := &config.Config{
		DataDir: tempDir,
	}

	sc := NewScanner(database, cfg)
	err = sc.EnsureLocalSegmentAutoRegistered()
	if err != nil {
		t.Fatalf("EnsureLocalSegmentAutoRegistered failed: %v", err)
	}

	segments, err := database.ListSegments()
	if err != nil {
		t.Fatalf("ListSegments failed: %v", err)
	}

	// Filter custom segments (excluding is_default=1 '未分類')
	var customSegs []*db.Segment
	for _, s := range segments {
		if !s.IsDefault && s.CIDR != "" {
			customSegs = append(customSegs, s)
		}
	}

	if len(customSegs) > 0 {
		// At least one segment should be enabled (the default gateway one)
		hasEnabled := false
		for _, s := range customSegs {
			if s.IsEnabled {
				hasEnabled = true
				break
			}
		}
		if !hasEnabled {
			t.Errorf("expected at least one segment to be enabled as default gateway, but all were disabled")
		}
	}
}

func TestDetermineDeviceProfile(t *testing.T) {
	tests := []struct {
		name     string
		vendor   string
		osVendor string
		hostname string
		ttl      int
		expected DeviceProfile
	}{
		{
			name:     "Apple Mac Laptop",
			vendor:   "Apple, Inc.",
			osVendor: "macOS Sonoma",
			hostname: "Hiroshi-MacBook-Pro.local",
			ttl:      64,
			expected: ProfileAppleMac,
		},
		{
			name:     "Apple iPhone",
			vendor:   "Apple, Inc.",
			osVendor: "iOS 17.5",
			hostname: "iPhone-User.local",
			ttl:      64,
			expected: ProfileAppleMobile,
		},
		{
			name:     "Windows 11 PC via TTL",
			vendor:   "Dell Inc.",
			osVendor: "",
			hostname: "DESKTOP-ABC1234",
			ttl:      128,
			expected: ProfileWindows,
		},
		{
			name:     "Windows PC via OS Vendor",
			vendor:   "Intel",
			osVendor: "Windows 10",
			hostname: "win-pc",
			ttl:      0,
			expected: ProfileWindows,
		},
		{
			name:     "Canon Network Printer",
			vendor:   "CANON INC.",
			osVendor: "",
			hostname: "canon-printer.local",
			ttl:      64,
			expected: ProfilePrinter,
		},
		{
			name:     "Epson Printer via Hostname",
			vendor:   "Seiko Epson Corp.",
			osVendor: "",
			hostname: "EPSON-L3150",
			ttl:      64,
			expected: ProfilePrinter,
		},
		{
			name:     "Synology NAS",
			vendor:   "Synology Incorporated",
			osVendor: "",
			hostname: "DS920-Vault",
			ttl:      64,
			expected: ProfileNASLinux,
		},
		{
			name:     "Buffalo Wi-Fi Router",
			vendor:   "BUFFALO.INC",
			osVendor: "",
			hostname: "WSR-3200AX4S",
			ttl:      64,
			expected: ProfileNetwork,
		},
		{
			name:     "Cisco Switch via TTL",
			vendor:   "",
			osVendor: "",
			hostname: "cisco-core",
			ttl:      255,
			expected: ProfileNetwork,
		},
		{
			name:     "Google Chromecast / Home",
			vendor:   "Google, Inc.",
			osVendor: "",
			hostname: "Living-Room-Speaker",
			ttl:      64,
			expected: ProfileMediaIoT,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetermineDeviceProfile(tt.vendor, tt.osVendor, tt.hostname, tt.ttl)
			if got != tt.expected {
				t.Errorf("DetermineDeviceProfile(%q, %q, %q, %d) = %v, expected %v",
					tt.vendor, tt.osVendor, tt.hostname, tt.ttl, got, tt.expected)
			}
		})
	}
}

func TestAdaptiveTargetPorts(t *testing.T) {
	// 1. Apple Mac must have SSH(22), SMB(445), VNC(5900), TeamViewer(5938), AnyDesk(7070), but NOT Windows RDP(3389) or Printer(9100)
	macPorts := GetTargetPortsForProfile(ProfileAppleMac)
	if _, ok := macPorts[22]; !ok {
		t.Errorf("expected SSH(22) in Apple Mac profile")
	}
	if _, ok := macPorts[445]; !ok {
		t.Errorf("expected SMB(445) in Apple Mac profile")
	}
	if _, ok := macPorts[5900]; !ok {
		t.Errorf("expected VNC(5900) in Apple Mac profile")
	}
	if _, ok := macPorts[5938]; !ok {
		t.Errorf("expected TeamViewer(5938) in Apple Mac profile")
	}
	if _, ok := macPorts[7070]; !ok {
		t.Errorf("expected AnyDesk(7070) in Apple Mac profile")
	}
	if _, ok := macPorts[3389]; ok {
		t.Errorf("unexpected Windows RDP(3389) in Apple Mac profile")
	}
	if _, ok := macPorts[9100]; ok {
		t.Errorf("unexpected RAW Printer(9100) in Apple Mac profile")
	}

	// 2. Windows must have SMB(445), RDP(3389), PPTP(1723), SoftEther(5555), VNC(5900), TeamViewer(5938), AnyDesk(7070), but NOT Apple AFP(548)
	winPorts := GetTargetPortsForProfile(ProfileWindows)
	if _, ok := winPorts[445]; !ok {
		t.Errorf("expected SMB(445) in Windows profile")
	}
	if _, ok := winPorts[3389]; !ok {
		t.Errorf("expected RDP(3389) in Windows profile")
	}
	if _, ok := winPorts[1723]; !ok {
		t.Errorf("expected PPTP(1723) in Windows profile")
	}
	if _, ok := winPorts[5555]; !ok {
		t.Errorf("expected SoftEther(5555) in Windows profile")
	}
	if _, ok := winPorts[5900]; !ok {
		t.Errorf("expected VNC(5900) in Windows profile")
	}
	if _, ok := winPorts[5938]; !ok {
		t.Errorf("expected TeamViewer(5938) in Windows profile")
	}
	if _, ok := winPorts[7070]; !ok {
		t.Errorf("expected AnyDesk(7070) in Windows profile")
	}
	if _, ok := winPorts[548]; ok {
		t.Errorf("unexpected AFP(548) in Windows profile")
	}

	// 3. Printer must have IPP(631) and RAW(9100), but NOT SSH(22) or RDP(3389)
	printerPorts := GetTargetPortsForProfile(ProfilePrinter)
	if _, ok := printerPorts[631]; !ok {
		t.Errorf("expected IPP(631) in Printer profile")
	}
	if _, ok := printerPorts[9100]; !ok {
		t.Errorf("expected RAW(9100) in Printer profile")
	}
	if _, ok := printerPorts[22]; ok {
		t.Errorf("unexpected SSH(22) in Printer profile")
	}
	if _, ok := printerPorts[3389]; ok {
		t.Errorf("unexpected RDP(3389) in Printer profile")
	}

	// 4. Apple Mobile must have 0 target ports (stealth preservation)
	mobilePorts := GetTargetPortsForProfile(ProfileAppleMobile)
	if len(mobilePorts) != 0 {
		t.Errorf("expected 0 ports for Apple Mobile, got %d", len(mobilePorts))
	}
}

func TestScanOpenPortsLowNoise(t *testing.T) {
	// Scan loopback on mobile profile (should be empty immediately)
	resMobile := ScanOpenPortsLowNoise("127.0.0.1", ProfileAppleMobile, 10*time.Millisecond, 5*time.Millisecond)
	if resMobile != "" {
		t.Errorf("expected empty string for mobile profile, got %s", resMobile)
	}

	// Scan loopback on generic profile with very small timeout/delay
	_ = ScanOpenPortsLowNoise("127.0.0.1", ProfileGeneric, 10*time.Millisecond, 5*time.Millisecond)

	// Risk evaluation check
	vpnRisk := EvaluatePortRisk(5555, "SoftEther VPN")
	if vpnRisk.Level != RiskCritical {
		t.Errorf("expected critical for SoftEther 5555, got %s", vpnRisk.Level)
	}

	rdpRisk := EvaluatePortRisk(3389, "RDP")
	if rdpRisk.Level != RiskWarning {
		t.Errorf("expected warning for RDP 3389, got %s", rdpRisk.Level)
	}

	sshRisk := EvaluatePortRisk(22, "SSH")
	if sshRisk.Level != RiskWarning {
		t.Errorf("expected warning for SSH 22, got %s", sshRisk.Level)
	}

	webRisk := EvaluatePortRisk(80, "HTTP")
	if webRisk.Level != RiskInfo {
		t.Errorf("expected info for HTTP 80, got %s", webRisk.Level)
	}
}

