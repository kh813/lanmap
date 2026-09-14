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
		name      string
		hostname  string
		mdnsModel string
		upnpName  string
		expected  string
	}{
		{
			name:     "Apostrophe S (English)",
			hostname: "Taro's MacBook Pro.local",
			expected: "Taro",
		},
		{
			name:     "Apostrophe S (Japanese)",
			hostname: "田中's iPhone",
			expected: "田中",
		},
		{
			name:     "No Device connector",
			hostname: "Taro-no-iPhone",
			expected: "Taro",
		},
		{
			name:     "Device prefix pattern",
			hostname: "pc-suzuki.lan",
			expected: "suzuki",
		},
		{
			name:     "Device suffix pattern",
			hostname: "yamada-laptop",
			expected: "yamada",
		},
		{
			name:     "Blacklist generic desktop",
			hostname: "DESKTOP-ABC1234",
			expected: "",
		},
		{
			name:     "Blacklist generic guest",
			hostname: "guest-wifi-device",
			expected: "",
		},
		{
			name:     "Blacklist pure device name",
			hostname: "iPhone",
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ExtractUserHint(tt.hostname, tt.mdnsModel, tt.upnpName)
			if got != tt.expected {
				t.Errorf("ExtractUserHint(%q) = %q, expected %q", tt.hostname, got, tt.expected)
			}
		})
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

	// 2. Apple Mac: mDNS model + Apple OUI + TTL 64
	macInput := OSScoreInput{
		IP:        "192.168.1.120",
		Hostname:  "taro-mbp.local",
		Vendor:    "Apple, Inc.",
		TTL:       64,
		MDNSModel: "MacBookPro18,4",
	}
	resMac := ScoreOS(macInput)
	if !strings.Contains(resMac.OS, "macOS") {
		t.Errorf("expected macOS, got %+v", resMac)
	}
	if resMac.Confidence != "high" {
		t.Errorf("expected high confidence, got %q", resMac.Confidence)
	}

	// 3. Router: Web Title LuCI + Network TTL
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
}
