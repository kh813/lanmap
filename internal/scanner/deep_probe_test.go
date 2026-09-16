package scanner

import (
	"encoding/binary"
	"fmt"
	"testing"
	"unicode/utf16"
)

func TestParseNTLMSSPType2(t *testing.T) {
	// Build a mock NTLMSSP Type 2 packet with Target Info
	// AV_PAIR 1: ComputerName = "THINKPAD-X1"
	// AV_PAIR 3: DNSHostName = "thinkpad-x1.corp.local"
	// AV_PAIR 2: DomainName = "CORP"
	var avBuf []byte

	encodeAV := func(id uint16, s string) []byte {
		u := utf16.Encode([]rune(s))
		raw := make([]byte, len(u)*2)
		for i, v := range u {
			binary.LittleEndian.PutUint16(raw[i*2:i*2+2], v)
		}
		var b []byte
		hdr := make([]byte, 4)
		binary.LittleEndian.PutUint16(hdr[0:2], id)
		binary.LittleEndian.PutUint16(hdr[2:4], uint16(len(raw)))
		b = append(b, hdr...)
		b = append(b, raw...)
		return b
	}

	avBuf = append(avBuf, encodeAV(0x0001, "THINKPAD-X1")...)
	avBuf = append(avBuf, encodeAV(0x0003, "thinkpad-x1.corp.local")...)
	avBuf = append(avBuf, encodeAV(0x0002, "CORP")...)
	avBuf = append(avBuf, []byte{0x00, 0x00, 0x00, 0x00}...) // EOL

	// NTLMSSP Type 2 header:
	// 0..7: "NTLMSSP\x00"
	// 8..11: msgType = 2
	// 40..47: Target Info Len=len(avBuf), MaxLen=len(avBuf), Offset=56
	// 48..55: OS Version Major=10, Minor=0, Build=22631, Reserved, NTLMRev=15
	hdr := make([]byte, 56)
	copy(hdr[0:8], []byte("NTLMSSP\x00"))
	binary.LittleEndian.PutUint32(hdr[8:12], 2)
	binary.LittleEndian.PutUint16(hdr[40:42], uint16(len(avBuf)))
	binary.LittleEndian.PutUint16(hdr[42:44], uint16(len(avBuf)))
	binary.LittleEndian.PutUint32(hdr[44:48], 56) // offset
	hdr[48] = 10                                 // Major
	hdr[49] = 0                                  // Minor
	binary.LittleEndian.PutUint16(hdr[50:52], 22631)

	packet := append(hdr, avBuf...)

	info := parseNTLMSSPType2(packet, SMBDeviceInfo{})
	if info.ComputerName != "THINKPAD-X1" {
		t.Errorf("expected ComputerName THINKPAD-X1, got %q", info.ComputerName)
	}
	if info.DNSHostName != "thinkpad-x1.corp.local" {
		t.Errorf("expected DNSHostName thinkpad-x1.corp.local, got %q", info.DNSHostName)
	}
	if info.DomainName != "CORP" {
		t.Errorf("expected DomainName CORP, got %q", info.DomainName)
	}
	if info.OSVersion != "Windows 11 (Build 22631)" {
		t.Errorf("expected OSVersion Windows 11 (Build 22631), got %q", info.OSVersion)
	}
}

func TestParseWSDXML(t *testing.T) {
	sampleWSD := `<?xml version="1.0" encoding="utf-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope"
               xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery"
               xmlns:dp="http://schemas.xmlsoap.org/ws/2006/02/devprof">
  <soap:Body>
    <wsd:ProbeMatches>
      <wsd:ProbeMatch>
        <dp:Manufacturer>Lenovo</dp:Manufacturer>
        <dp:ModelName>ThinkPad X1 Carbon Gen 10</dp:ModelName>
        <dp:ModelNumber>21CB000EJP</dp:ModelNumber>
        <dp:FriendlyName>HIROSHI-X1C</dp:FriendlyName>
      </wsd:ProbeMatch>
    </wsd:ProbeMatches>
  </soap:Body>
</soap:Envelope>`

	info := parseWSDXML(sampleWSD)
	if info == nil {
		t.Fatalf("parseWSDXML returned nil")
	}
	if info.Manufacturer != "Lenovo" {
		t.Errorf("expected Manufacturer Lenovo, got %q", info.Manufacturer)
	}
	if info.ModelName != "ThinkPad X1 Carbon Gen 10" {
		t.Errorf("expected ModelName 'ThinkPad X1 Carbon Gen 10', got %q", info.ModelName)
	}
	if info.FriendlyName != "HIROSHI-X1C" {
		t.Errorf("expected FriendlyName HIROSHI-X1C, got %q", info.FriendlyName)
	}
}

func TestSynthesizeDeepHostAttributes(t *testing.T) {
	// Test full Windows PC resolution scenario with WSD + SMB + NetBIOS
	mdnsInfo := MDNSDeviceInfo{}
	nbInfo := NetBIOSInfo{
		ComputerName: "DESKTOP-7K9L2MZ",
		UserName:     "HIROSHI",
		Workgroup:    "WORKGROUP",
		IsWindows:    true,
	}
	smbInfo := SMBDeviceInfo{
		ComputerName: "DESKTOP-7K9L2MZ",
		DNSHostName:  "hiroshi-x1c.corp.lan",
		OSVersion:    "Windows 11 (Build 26100)",
	}
	wsdInfo := &WSDDeviceInfo{
		Manufacturer: "Lenovo",
		ModelName:    "ThinkPad X1 Carbon Gen 10",
		FriendlyName: "hiroshi-x1c",
	}
	var snmpInfo *SNMPDeviceInfo

	signals := SynthesizeDeepHostAttributes(
		"192.168.1.50", "DESKTOP-7K9L2MZ", "Intel Corporate", "",
		128, "135,139,445,5357", "", "", "", "",
		mdnsInfo, nbInfo, smbInfo, wsdInfo, snmpInfo,
	)

	if signals.Hostname != "hiroshi-x1c.corp.lan" {
		t.Errorf("expected Hostname 'hiroshi-x1c.corp.lan', got %q", signals.Hostname)
	}
	if signals.VendorModel != "Lenovo ThinkPad X1 Carbon Gen 10" {
		t.Errorf("expected VendorModel 'Lenovo ThinkPad X1 Carbon Gen 10', got %q", signals.VendorModel)
	}
	if signals.OSVendor != "Windows 11 (Build 26100)" {
		t.Errorf("expected OSVendor 'Windows 11 (Build 26100)', got %q", signals.OSVendor)
	}
	if signals.UserHint != "HIROSHI" {
		t.Errorf("expected UserHint 'HIROSHI', got %q", signals.UserHint)
	}
}

func TestResolveWindowsModelSurfaceAndThinkPad(t *testing.T) {
	// Surface Pro 11 / Copilot+
	m1 := ResolveWindowsModel("Surface Pro 11th Edition", "", "", "Microsoft Corporation")
	if m1 != "Microsoft Surface Pro (11th Edition / Copilot+ PC)" {
		t.Errorf("expected Surface Pro 11th Edition, got %q", m1)
	}

	// ThinkPad X1 Carbon Gen 10
	m2 := ResolveWindowsModel("", "", "thinkpad-x1-carbon-gen-10", "Intel Corporate")
	if m2 != "Lenovo ThinkPad X1 Carbon Gen 10" {
		t.Errorf("expected Lenovo ThinkPad X1 Carbon Gen 10, got %q", m2)
	}
}

func TestNetBIOSComputerNameVsUserName(t *testing.T) {
	// Mock NBSTAT response where <03> has the same name as <00> ComputerName
	// Header (12 bytes) + NBSTAT RR
	hdr := make([]byte, 12)
	hdr[6] = 0x00 // Answer RRs = 1
	hdr[7] = 0x01

	// Answer RR: Type=0x0021, Class=0x0001, TTL=0, RDLength=...
	var ans []byte
	ans = append(ans, 0x00)                                                       // Root name
	ans = append(ans, []byte{0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}...) // Type NBSTAT, Class IN, TTL 0
	ans = append(ans, []byte{0x00, 0x44}...)                                     // RDLength = 68 (1 + 3*18 + 6)
	ans = append(ans, 0x03)                                                      // 3 names

	formatName := func(name string, suffix byte, isGroup bool) []byte {
		b := make([]byte, 18)
		copy(b, []byte(fmt.Sprintf("%-15s", name)))
		b[15] = suffix
		if isGroup {
			b[16] = 0x80
		}
		return b
	}

	// 1. DESKTOP-PC <00> Unique
	ans = append(ans, formatName("DESKTOP-PC", 0x00, false)...)
	// 2. WORKGROUP  <00> Group
	ans = append(ans, formatName("WORKGROUP", 0x00, true)...)
	// 3. DESKTOP-PC <03> Unique (same as computer name)
	ans = append(ans, formatName("DESKTOP-PC", 0x03, false)...)
	// Unit ID (MAC: 00:11:22:33:44:55)
	ans = append(ans, []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}...)

	packet := append(hdr, ans...)
	info := ParseNetBIOSNodeStatus(packet)

	if info.ComputerName != "DESKTOP-PC" {
		t.Errorf("expected ComputerName DESKTOP-PC, got %q", info.ComputerName)
	}
	if info.UserName != "" {
		t.Errorf("expected empty UserName when <03> matches ComputerName, got %q", info.UserName)
	}

	// Now test when <03> has an actual logged-in user name
	ans2 := []byte{0x00}
	ans2 = append(ans2, []byte{0x00, 0x21, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x44, 0x03}...)
	ans2 = append(ans2, formatName("DESKTOP-PC", 0x00, false)...)
	ans2 = append(ans2, formatName("WORKGROUP", 0x00, true)...)
	ans2 = append(ans2, formatName("HIROSHI", 0x03, false)...)
	ans2 = append(ans2, []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55}...)

	packet2 := append(hdr, ans2...)
	info2 := ParseNetBIOSNodeStatus(packet2)

	if info2.ComputerName != "DESKTOP-PC" {
		t.Errorf("expected ComputerName DESKTOP-PC, got %q", info2.ComputerName)
	}
	if info2.UserName != "HIROSHI" {
		t.Errorf("expected UserName HIROSHI, got %q", info2.UserName)
	}
}

func TestExtractUserHintNoBogusHostname(t *testing.T) {
	// Plain hostnames should NEVER be treated as user hints
	if h := ExtractUserHint("", "THINKPAD"); h != "" {
		t.Errorf("expected empty user hint for 'THINKPAD', got %q", h)
	}
	if h := ExtractUserHint("", "HONBU-PC"); h != "" {
		t.Errorf("expected empty user hint for 'HONBU-PC', got %q", h)
	}
	if h := ExtractUserHint("", "FILESERVER"); h != "" {
		t.Errorf("expected empty user hint for 'FILESERVER', got %q", h)
	}
	if h := ExtractUserHint("", "VAIO"); h != "" {
		t.Errorf("expected empty user hint for 'VAIO', got %q", h)
	}
	if h := ExtractUserHint("", "openwrt.parkside.tokyo"); h != "" {
		t.Errorf("expected empty user hint for 'openwrt.parkside.tokyo', got %q", h)
	}
	if h := ExtractUserHint("", "pfsense.home.arpa"); h != "" {
		t.Errorf("expected empty user hint for 'pfsense.home.arpa', got %q", h)
	}
	if h := ExtractUserHint("", "synology"); h != "" {
		t.Errorf("expected empty user hint for 'synology', got %q", h)
	}

	// Pattern-based hostnames SHOULD be extracted
	if h := ExtractUserHint("", "pc-suzuki"); h != "suzuki" {
		t.Errorf("expected 'suzuki' for 'pc-suzuki', got %q", h)
	}
	if h := ExtractUserHint("", "Hiroshi's MacBook Pro"); h != "Hiroshi" {
		t.Errorf("expected 'Hiroshi' for \"Hiroshi's MacBook Pro\", got %q", h)
	}

	// Explicit NetBIOS / DHCP username SHOULD be extracted
	if h := ExtractUserHint("HIROSHI", "DESKTOP-PC"); h != "HIROSHI" {
		t.Errorf("expected 'HIROSHI' when explicit username is provided, got %q", h)
	}
}

