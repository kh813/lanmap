package scanner

import (
	"strings"
	"testing"
)

func TestLookupDHCPFingerprint(t *testing.T) {
	// 1. Windows 11 typical Option 55
	winParams := []byte{1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252}
	resWin := LookupDHCPFingerprint(winParams, "", "my-pc")
	if resWin == nil || !strings.Contains(resWin.OS, "Windows") {
		t.Errorf("expected Windows OS, got %+v", resWin)
	}
	if resWin.Confidence < 0.9 {
		t.Errorf("expected high confidence for exact match, got %f", resWin.Confidence)
	}

	// 2. Apple iOS / macOS typical Option 55
	appleParams := []byte{1, 121, 3, 6, 15, 114, 119, 252}
	resApple := LookupDHCPFingerprint(appleParams, "", "Taro-iPhone")
	if resApple == nil || !strings.Contains(resApple.OS, "iOS") {
		t.Errorf("expected iOS, got %+v", resApple)
	}

	// 3. Option 60 Vendor Class (Nintendo Switch)
	resSwitch := LookupDHCPFingerprint(nil, "Nintendo Switch", "Switch")
	if resSwitch == nil || !strings.Contains(resSwitch.OS, "Nintendo Switch") {
		t.Errorf("expected Nintendo Switch, got %+v", resSwitch)
	}

	// 4. Android Option 55
	androidParams := []byte{1, 3, 6, 15, 26, 28, 51, 58, 59, 43}
	resAndroid := LookupDHCPFingerprint(androidParams, "", "Pixel-8")
	if resAndroid == nil || !strings.Contains(resAndroid.OS, "Android") {
		t.Errorf("expected Android, got %+v", resAndroid)
	}
}

func TestExtractUserHint(t *testing.T) {
	tests := []struct {
		name     string
		sources  []string
		expected string
	}{
		{
			name:     "Apostrophe S (English)",
			sources:  []string{"Taro's MacBook Pro.local"},
			expected: "Taro",
		},
		{
			name:     "Apostrophe S (Japanese)",
			sources:  []string{"田中's iPhone"},
			expected: "田中",
		},
		{
			name:     "Japanese particle no with Kanji name",
			sources:  []string{"山田太郎のMacBook"},
			expected: "山田太郎",
		},
		{
			name:     "Japanese particle no with spaces",
			sources:  []string{"佐藤 の iPad"},
			expected: "佐藤",
		},
		{
			name:     "No Device connector ASCII",
			sources:  []string{"Taro-no-iPhone"},
			expected: "Taro",
		},
		{
			name:     "Parenthesized name (Device prefix)",
			sources:  []string{"MacBook Pro (Hiroshi)"},
			expected: "Hiroshi",
		},
		{
			name:     "Parenthesized device (Name prefix)",
			sources:  []string{"田中 (iPhone)"},
			expected: "田中",
		},
		{
			name:     "Device prefix pattern",
			sources:  []string{"pc-suzuki.lan"},
			expected: "suzuki",
		},
		{
			name:     "Device suffix pattern with Silicon gen",
			sources:  []string{"hiroshi-m3"},
			expected: "hiroshi",
		},
		{
			name:     "Device suffix pattern with laptop",
			sources:  []string{"yamada-laptop"},
			expected: "yamada",
		},
		{
			name:     "Hyphenated s pattern",
			sources:  []string{"taros-macbook-pro"},
			expected: "taro",
		},
		{
			name:     "French/Spanish de connector",
			sources:  []string{"MacBook-de-Pierre"},
			expected: "Pierre",
		},
		{
			name:     "mDNS DeviceName priority",
			sources:  []string{"dhcp-192-168-1-50", "Hiroshi’s MacBook Pro", "MacBook Pro (14-inch, M3 Pro, Nov 2023)"},
			expected: "Hiroshi",
		},
		{
			name:     "Blacklist generic desktop",
			sources:  []string{"DESKTOP-ABC1234"},
			expected: "",
		},
		{
			name:     "Blacklist generic guest",
			sources:  []string{"guest-wifi-device"},
			expected: "",
		},
		{
			name:     "Blacklist pure device name",
			sources:  []string{"iPhone", "MacBook Pro"},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractUserHint(tt.sources...)
			if got != tt.expected {
				t.Errorf("ExtractUserHint(%v) = %q, expected %q", tt.sources, got, tt.expected)
			}
		})
	}
}

func TestResolveMDNSModelAndDarwin(t *testing.T) {
	// Test M4 / M3 / M2 models
	tests := []struct {
		rawModel string
		expected string
	}{
		{"Mac16,1", "MacBook Pro (14-inch, M4, 2024)"},
		{"Mac16,10", "Mac mini (M4, 2024)"},
		{"Mac15,3", "MacBook Pro (14-inch, M3, Nov 2023)"},
		{"Mac14,2", "MacBook Air (13-inch, M2, 2022)"},
		{"MacBookPro18,4", "MacBook Pro (14-inch, 2021 M1 Max)"},
		{"iPad16,3", "iPad Pro 11-inch (M4, 2024)"},
		{"iPhone17,1", "iPhone 16 Pro"},
		{"UnknownModel99,9", "Model: UnknownModel99,9"},
	}

	for _, tt := range tests {
		got := ResolveMDNSModel(tt.rawModel)
		if got != tt.expected {
			t.Errorf("ResolveMDNSModel(%q) = %q, expected %q", tt.rawModel, got, tt.expected)
		}
	}

	// Test Darwin version mapping
	darwinTests := []struct {
		osxvers  string
		expected string
	}{
		{"24", "macOS 15 Sequoia"},
		{"24.1.0", "macOS 15 Sequoia"},
		{"23", "macOS 14 Sonoma"},
		{"22", "macOS 13 Ventura"},
		{"21", "macOS 12 Monterey"},
		{"20", "macOS 11 Big Sur"},
		{"19", "macOS 10.15 Catalina"},
	}

	for _, dt := range darwinTests {
		got := ResolveMacOSVersion(dt.osxvers)
		if got != dt.expected {
			t.Errorf("ResolveMacOSVersion(%q) = %q, expected %q", dt.osxvers, got, dt.expected)
		}
	}
}

func TestParseMDNSDeviceInfoPayload(t *testing.T) {
	// Build simulated mDNS DNS response packet for an Apple Silicon MacBook
	// PTR: "Hiroshi’s MacBook Pro._device-info._tcp.local"
	// TXT: "model=Mac15,3" and "osxvers=24"
	instanceName := "Hiroshi’s MacBook Pro"
	var buf []byte
	buf = append(buf, 0x00, 0x00, 0x84, 0x00) // Flags: Standard response
	buf = append(buf, 0x00, 0x00, 0x00, 0x01) // 1 answer
	buf = append(buf, 0x00, 0x00, 0x00, 0x01) // 1 additional

	// Instance label length byte + string
	buf = append(buf, byte(len(instanceName)))
	buf = append(buf, []byte(instanceName)...)
	// _device-info._tcp.local
	buf = append(buf, 0x0c)
	buf = append(buf, []byte("_device-info")...)
	buf = append(buf, 0x04)
	buf = append(buf, []byte("_tcp")...)
	buf = append(buf, 0x05)
	buf = append(buf, []byte("local")...)
	buf = append(buf, 0x00)

	// TXT record part
	txtContent := "\x0dmodel=Mac15,3\x0aosxvers=24"
	buf = append(buf, []byte(txtContent)...)

	parsed := ParseMDNSDeviceInfoPayload(buf)
	if parsed.RawModel != "Mac15,3" {
		t.Errorf("expected RawModel Mac15,3, got %q", parsed.RawModel)
	}
	if parsed.Model != "MacBook Pro (14-inch, M3, Nov 2023)" {
		t.Errorf("expected Model MacBook Pro (14-inch, M3, Nov 2023), got %q", parsed.Model)
	}
	if parsed.OSXVers != "24" {
		t.Errorf("expected OSXVers 24, got %q", parsed.OSXVers)
	}
	if parsed.MacOSVer != "macOS 15 Sequoia" {
		t.Errorf("expected MacOSVer macOS 15 Sequoia, got %q", parsed.MacOSVer)
	}
	if parsed.DeviceName != instanceName {
		t.Errorf("expected DeviceName %q, got %q", instanceName, parsed.DeviceName)
	}
	if !parsed.IsApple {
		t.Errorf("expected IsApple true, got false")
	}
}

func TestScoreOS(t *testing.T) {
	// 1. Windows: TTL 128 + SMB 445 + DHCP Option 55
	winInput := OSScoreInput{
		IP:            "192.168.1.110",
		Hostname:      "pc-sato",
		Vendor:        "Intel",
		TTL:           128,
		OpenPorts:     "135,139,445",
		DHCPParamList: []byte{1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252},
	}
	resWin := ScoreOS(winInput)
	if !strings.Contains(resWin.OS, "Windows") {
		t.Errorf("expected Windows OS, got %+v", resWin)
	}
	if resWin.Confidence != "high" {
		t.Errorf("expected high confidence, got %q", resWin.Confidence)
	}
	if !strings.Contains(resWin.Evidence, "DHCP Option 55") || !strings.Contains(resWin.Evidence, "445") {
		t.Errorf("expected Evidence to mention Option 55 and Port 445, got %q", resWin.Evidence)
	}

	// 2. Apple Mac with exact macOS version from mDNS
	macInput := OSScoreInput{
		IP:         "192.168.1.120",
		Hostname:   "hiroshi-mbp.local",
		Vendor:     "Apple, Inc.",
		TTL:        64,
		MDNSModel:  "MacBook Pro (14-inch, M3 Pro, Nov 2023)",
		MDNSDevice: "Hiroshi’s MacBook Pro",
		MacOSVer:   "macOS 15 Sequoia",
	}
	resMac := ScoreOS(macInput)
	if resMac.OS != "macOS 15 Sequoia" {
		t.Errorf("expected 'macOS 15 Sequoia', got %+v", resMac)
	}
	if resMac.Confidence != "high" {
		t.Errorf("expected high confidence, got %q", resMac.Confidence)
	}

	// 3. Linux / Avahi host (TTL 64, port 22, no Apple mDNS records)
	linuxInput := OSScoreInput{
		IP:        "192.168.1.5",
		Hostname:  "ubuntu-server.local",
		TTL:       64,
		OpenPorts: "22:SSH",
	}
	resLinux := ScoreOS(linuxInput)
	if !strings.Contains(resLinux.OS, "Linux") {
		t.Errorf("expected Linux for SSH host with TTL 64, got %+v", resLinux)
	}

	// 4. Router: Web Title LuCI + Network TTL
	routerInput := OSScoreInput{
		IP:        "192.168.1.1",
		Hostname:  "router.lan",
		Vendor:    "Netgear",
		TTL:       64,
		HTTPTitle: "OpenWrt - LuCI 23.05",
		OpenPorts: "80:HTTP,443:HTTPS",
	}
	resRouter := ScoreOS(routerInput)
	if !strings.Contains(resRouter.OS, "OpenWrt") {
		t.Errorf("expected OpenWrt, got %+v", resRouter)
	}
	if resRouter.Confidence != "high" {
		t.Errorf("expected high confidence, got %q", resRouter.Confidence)
	}

	// 5. Windows determined purely by Ping TTL 128
	winTTLOnly := OSScoreInput{
		IP:       "192.168.1.130",
		Hostname: "desktop-win",
		TTL:      128,
	}
	resWinTTL := ScoreOS(winTTLOnly)
	if resWinTTL.OS != "Windows" {
		t.Errorf("expected Windows from TTL 128, got %+v", resWinTTL)
	}
	if resWinTTL.Confidence != "medium" {
		t.Errorf("expected medium confidence from TTL 128, got %q", resWinTTL.Confidence)
	}

	// 6. Host with no ping response (TTL 0) and no other evidence -> Unknown (empty string)
	noSignalInput := OSScoreInput{
		IP:  "192.168.1.140",
		TTL: 0,
	}
	resNoSignal := ScoreOS(noSignalInput)
	if resNoSignal.OS != "" {
		t.Errorf("expected empty OS (Unknown/Not Detected) for no signals, got %+v", resNoSignal)
	}

	// 8. Fortinet FortiGate Firewall
	fortiInput := OSScoreInput{
		IP:        "192.168.1.254",
		Hostname:  "FGT60F-HQ",
		Vendor:    "Fortinet (FortiGate)",
		TTL:       255,
		HTTPTitle: "FortiGate - Administrative Access",
		OpenPorts: "443:HTTPS,541:FortiTelemetry",
	}
	resForti := ScoreOS(fortiInput)
	if !strings.Contains(resForti.OS, "FortiOS") {
		t.Errorf("expected FortiOS, got %+v", resForti)
	}
	if resForti.Confidence != "high" {
		t.Errorf("expected high confidence for FortiGate, got %q", resForti.Confidence)
	}

	// 9. Aruba Wireless Access Point
	arubaInput := OSScoreInput{
		IP:        "192.168.1.10",
		Hostname:  "Aruba-AP-515",
		Vendor:    "Aruba Networks (HPE)",
		TTL:       64,
		HTTPTitle: "Aruba Instant On WebUI",
	}
	resAruba := ScoreOS(arubaInput)
	if !strings.Contains(resAruba.OS, "ArubaOS") {
		t.Errorf("expected ArubaOS, got %+v", resAruba)
	}

	// 10. Mist Systems AP
	mistInput := OSScoreInput{
		IP:       "192.168.1.11",
		Hostname: "AP43-Lobby",
		Vendor:   "Mist Systems (Juniper)",
		TTL:      64,
	}
	resMist := ScoreOS(mistInput)
	if !strings.Contains(resMist.OS, "Mist AI") {
		t.Errorf("expected Mist AI, got %+v", resMist)
	}

	// 11. Hikvision Surveillance Camera
	camInput := OSScoreInput{
		IP:        "192.168.1.200",
		Hostname:  "IPC-HDW4631C",
		Vendor:    "Hikvision (Camera)",
		TTL:       64,
		OpenPorts: "80:HTTP,554:RTSP,8000:Hikvision",
	}
	resCam := ScoreOS(camInput)
	if !strings.Contains(resCam.OS, "Hikvision") {
		t.Errorf("expected Hikvision Embedded Linux, got %+v", resCam)
	}

	// 12. Yealink VoIP Phone
	voipInput := OSScoreInput{
		IP:        "192.168.1.201",
		Hostname:  "Yealink-T46U",
		Vendor:    "Yealink (IP Phone)",
		TTL:       64,
		OpenPorts: "80:HTTP,5060:SIP",
	}
	resVoip := ScoreOS(voipInput)
	if !strings.Contains(resVoip.OS, "Yealink") {
		t.Errorf("expected Yealink VoIP OS, got %+v", resVoip)
	}

	// 13. SwitchBot IoT Device
	// 14. Multifunction Printer (MFP) with Samba/SMB enabled
	mfpInput := OSScoreInput{
		IP:          "192.168.1.150",
		Hostname:    "RICOH-IM-C3000",
		Vendor:      "Ricoh Company, Ltd.",
		OpenPorts:   "80:HTTP,445:SMB,9100:RAW,631:IPP",
		IsNetBIOS:   true,
		NetBIOSName: "RICOH-IMC3000",
		TTL:         64,
	}
	resMFP := ScoreOS(mfpInput)
	if !strings.Contains(resMFP.OS, "Printer Firmware") && !strings.Contains(resMFP.OS, "Ricoh") {
		t.Errorf("expected Printer Firmware for Ricoh MFP, got %+v", resMFP)
	}
	if strings.Contains(resMFP.OS, "Windows") {
		t.Errorf("MFP should not be classified as Windows, got %+v", resMFP)
	}

	// 15. Canon MFP with NetBIOS
	canonInput := OSScoreInput{
		IP:          "192.168.1.151",
		Hostname:    "CANON-IR-ADV-C3520",
		Vendor:      "Canon Inc.",
		OpenPorts:   "80:HTTP,445:SMB,515:LPD,9100:RAW",
		IsNetBIOS:   true,
		NetBIOSName: "CANON-ADV",
		TTL:         64,
	}
	resCanon := ScoreOS(canonInput)
	if !strings.Contains(resCanon.OS, "Printer") && !strings.Contains(resCanon.OS, "Canon") {
		t.Errorf("expected Printer for Canon MFP, got %+v", resCanon)
	}
	if strings.Contains(resCanon.OS, "Windows") {
		t.Errorf("Canon MFP should not be classified as Windows, got %+v", resCanon)
	}
}

func TestParseNetBIOSNodeStatus(t *testing.T) {
	// Build simulated NBSTAT response
	// Header: 12 bytes
	// Question: 34 bytes (Name len 32 + term) + 4 bytes
	// Answer: Pointer (2) + Type (2) + Class (2) + TTL (4) + RDLEN (2) = 12 bytes
	// NumNames: 1 byte (3 names)
	// Entry 1: "DESKTOP-ABC    \x00" (Type 0x00, Unique machine name)
	// Entry 2: "HIROSHI        \x03" (Type 0x03, Unique user name)
	// Entry 3: "WORKGROUP      \x00" (Type 0x00, Group workgroup name, flag 0x8000)
	// Unit ID: MAC Address 00:15:5d:aa:bb:cc (6 bytes)

	var buf []byte
	// 12 bytes Header
	buf = append(buf, 0x80, 0x94, 0x84, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00)
	// Answer header: Name pointer 0xc00c, Type 0x0021, Class 0x0001, TTL 0, RDLEN 60
	buf = append(buf, 0xc0, 0x0c, 0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x3c)
	// Number of names = 3
	buf = append(buf, 0x03)

	// Entry 1: Computer name (Type 0x00, unique)
	compName := "DESKTOP-ABC    "
	buf = append(buf, []byte(compName)...)
	buf = append(buf, 0x00, 0x04, 0x00) // Suffix 0x00, Flags 0x0400 (Unique)

	// Entry 2: User name (Type 0x03, unique)
	userName := "HIROSHI        "
	buf = append(buf, []byte(userName)...)
	buf = append(buf, 0x03, 0x04, 0x00) // Suffix 0x03, Flags 0x0400 (Unique)

	// Entry 3: Workgroup (Type 0x00, group)
	wgName := "WORKGROUP      "
	buf = append(buf, []byte(wgName)...)
	buf = append(buf, 0x00, 0x84, 0x00) // Suffix 0x00, Flags 0x8400 (Group)

	// Unit ID (MAC address): 00:15:5d:aa:bb:cc
	buf = append(buf, 0x00, 0x15, 0x5d, 0xaa, 0xbb, 0xcc)

	parsed := ParseNetBIOSNodeStatus(buf)
	if parsed.ComputerName != "DESKTOP-ABC" {
		t.Errorf("expected ComputerName DESKTOP-ABC, got %q", parsed.ComputerName)
	}
	if parsed.UserName != "HIROSHI" {
		t.Errorf("expected UserName HIROSHI, got %q", parsed.UserName)
	}
	if parsed.Workgroup != "WORKGROUP" {
		t.Errorf("expected Workgroup WORKGROUP, got %q", parsed.Workgroup)
	}
	if parsed.MACAddress != "00:15:5d:aa:bb:cc" {
		t.Errorf("expected MACAddress 00:15:5d:aa:bb:cc, got %q", parsed.MACAddress)
	}
	if !parsed.IsWindows {
		t.Errorf("expected IsWindows true, got false")
	}

	// Test user hint extraction from NetBIOS info
	hint := ExtractUserHint(parsed.UserName, parsed.ComputerName)
	if hint != "HIROSHI" {
		t.Errorf("expected user hint HIROSHI, got %q", hint)
	}
}

func TestDecodeNetBIOSName(t *testing.T) {
	// First-level encoded name for "TEST-PC        "
	// 'T' -> (0x54 >> 4) + 'A' = 0x5 + 'A' = 'F', (0x54 & 0x0F) + 'A' = 0x4 + 'A' = 'E' -> "FE"
	// 'E' -> 0x45 -> "EF"
	// 'S' -> 0x53 -> "FD"
	// 'T' -> 0x54 -> "FE"
	// '-' -> 0x2D -> "CN"
	// 'P' -> 0x50 -> "FA"
	// 'C' -> 0x43 -> "ED"
	// ' ' -> 0x20 -> "CA"
	encoded := "FEEFFDFECNFAEDCACACACACACACACACA"
	decoded := DecodeNetBIOSName(encoded)
	if decoded != "TEST-PC" {
		t.Errorf("expected decoded name TEST-PC, got %q", decoded)
	}
}

func TestResolveWindowsModel(t *testing.T) {
	tests := []struct {
		upnpModel string
		upnpName  string
		hostname  string
		vendor    string
		expected  string
	}{
		{
			upnpModel: "Surface Pro 9",
			vendor:    "Microsoft Corporation",
			expected:  "Microsoft Surface Pro 9",
		},
		{
			upnpModel: "ThinkPad X1 Carbon Gen 10",
			vendor:    "Lenovo",
			expected:  "Lenovo ThinkPad X1 Carbon",
		},
		{
			upnpName: "CF-SV9",
			vendor:   "Panasonic",
			expected: "Panasonic Let's note CF-SV Series",
		},
		{
			upnpName: "LIFEBOOK U9311",
			vendor:   "Fujitsu",
			expected: "Fujitsu LIFEBOOK U9300 Series (Ultralight)",
		},
		{
			upnpModel: "dynabook G83/HS",
			vendor:    "Dynabook Inc.",
			expected:  "Dynabook Business Mobile (G/RJ Series)",
		},
	}

	for _, tt := range tests {
		got := ResolveWindowsModel(tt.upnpModel, tt.upnpName, tt.hostname, tt.vendor)
		if got != tt.expected {
			t.Errorf("ResolveWindowsModel(%q, %q, %q, %q) = %q, expected %q",
				tt.upnpModel, tt.upnpName, tt.hostname, tt.vendor, got, tt.expected)
		}
	}
}
