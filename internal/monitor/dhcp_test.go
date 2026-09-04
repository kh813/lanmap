package monitor

import (
	"encoding/binary"
	"net"
	"path/filepath"
	"testing"

	"lanmap/internal/db"
	"lanmap/internal/notifier"
)

func buildTestDHCPPacket(op byte, chaddr net.HardwareAddr, ciaddr, yiaddr net.IP, options map[byte][]byte) []byte {
	buf := make([]byte, 240) // 236 header + 4 magic cookie
	buf[0] = op
	buf[1] = 1 // Ethernet
	buf[2] = 6 // MAC len

	binary.BigEndian.PutUint32(buf[4:8], 0x12345678)

	if ciaddr != nil {
		copy(buf[12:16], ciaddr.To4())
	}
	if yiaddr != nil {
		copy(buf[16:20], yiaddr.To4())
	}
	if chaddr != nil {
		copy(buf[28:34], chaddr)
	}

	// Magic Cookie
	copy(buf[236:240], DHCPMagicCookie)

	// Options
	for tag, data := range options {
		buf = append(buf, tag, byte(len(data)))
		buf = append(buf, data...)
	}
	buf = append(buf, 255) // END
	return buf
}

func TestParseDHCPPacket_Discover(t *testing.T) {
	mac, _ := net.ParseMAC("00:11:22:33:44:55")
	reqIP := net.ParseIP("192.168.1.105").To4()

	options := map[byte][]byte{
		53: {1}, // DHCPDISCOVER
		50: reqIP,
		12: []byte("Test-MacBook"),
		60: []byte("Apple, Inc. Darwin/23.0"),
		55: {1, 121, 3, 6, 15, 119, 252},
	}

	raw := buildTestDHCPPacket(1, mac, nil, nil, options)

	pkt, err := ParseDHCPPacket(raw)
	if err != nil {
		t.Fatalf("ParseDHCPPacket failed: %v", err)
	}

	if pkt.CHAddr != "00:11:22:33:44:55" {
		t.Errorf("expected MAC 00:11:22:33:44:55, got %s", pkt.CHAddr)
	}
	if pkt.RequestedIP == nil || pkt.RequestedIP.String() != "192.168.1.105" {
		t.Errorf("expected RequestedIP 192.168.1.105, got %v", pkt.RequestedIP)
	}
	if pkt.Hostname != "Test-MacBook" {
		t.Errorf("expected Hostname Test-MacBook, got %q", pkt.Hostname)
	}
	if pkt.VendorClass != "Apple, Inc. Darwin/23.0" {
		t.Errorf("expected VendorClass Apple, Inc. Darwin/23.0, got %q", pkt.VendorClass)
	}
	if pkt.MessageType != 1 {
		t.Errorf("expected MessageType 1 (DISCOVER), got %d", pkt.MessageType)
	}

	os := InferOSFromDHCP(pkt.VendorClass, pkt.ParamList)
	if os != "macOS/iOS" {
		t.Errorf("expected OS macOS/iOS, got %q", os)
	}
}

func TestParseDHCPPacket_Ack(t *testing.T) {
	mac, _ := net.ParseMAC("aa:bb:cc:dd:ee:ff")
	yiaddr := net.ParseIP("192.168.1.200").To4()

	options := map[byte][]byte{
		53: {5}, // DHCPACK
		12: []byte("DESKTOP-ABC\x00"),
		60: []byte("MSFT 5.0"),
		55: {1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252},
	}

	raw := buildTestDHCPPacket(2, mac, nil, yiaddr, options)

	pkt, err := ParseDHCPPacket(raw)
	if err != nil {
		t.Fatalf("ParseDHCPPacket failed: %v", err)
	}

	if pkt.CHAddr != "aa:bb:cc:dd:ee:ff" {
		t.Errorf("expected MAC aa:bb:cc:dd:ee:ff, got %s", pkt.CHAddr)
	}
	if pkt.YIAddr == nil || pkt.YIAddr.String() != "192.168.1.200" {
		t.Errorf("expected YIAddr 192.168.1.200, got %v", pkt.YIAddr)
	}
	if pkt.Hostname != "DESKTOP-ABC" {
		t.Errorf("expected clean Hostname DESKTOP-ABC, got %q", pkt.Hostname)
	}

	os := InferOSFromDHCP(pkt.VendorClass, pkt.ParamList)
	if os != "Windows" {
		t.Errorf("expected OS Windows, got %q", os)
	}
}

func TestParseDHCPPacket_Invalid(t *testing.T) {
	// Too short
	short := make([]byte, 100)
	if _, err := ParseDHCPPacket(short); err == nil {
		t.Errorf("expected error for short packet, got nil")
	}

	// Bad cookie
	badCookie := make([]byte, 240)
	copy(badCookie[236:240], []byte{0x01, 0x02, 0x03, 0x04})
	if _, err := ParseDHCPPacket(badCookie); err == nil {
		t.Errorf("expected error for invalid cookie, got nil")
	}
}

func TestDHCPMonitor_ProcessPacketAndDB(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_dhcp.db")
	database, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("Open DB failed: %v", err)
	}
	defer database.Close()

	// Create segment for 192.168.1.0/24
	seg, err := database.CreateSegment("Office LAN", "192.168.1.0/24", "eth0", true)
	if err != nil {
		t.Fatalf("CreateSegment failed: %v", err)
	}

	notif := notifier.NewNotifier(database)
	dm := NewDHCPMonitor(database, notif)

	mac, _ := net.ParseMAC("b8:27:eb:12:34:56") // Raspberry Pi OUI
	reqIP := net.ParseIP("192.168.1.55").To4()

	options := map[byte][]byte{
		53: {3}, // DHCPREQUEST
		50: reqIP,
		12: []byte("raspberrypi"),
		60: []byte("dhcpcd-9.4.1:Linux-5.10.103+"),
	}

	raw := buildTestDHCPPacket(1, mac, nil, nil, options)

	dm.ProcessPacket(raw, nil)

	// Verify host in DB
	h, err := database.GetHost("192.168.1.55")
	if err != nil || h == nil {
		t.Fatalf("Expected host 192.168.1.55 in DB, got: %v (err: %v)", h, err)
	}

	if h.MACAddress != "b8:27:eb:12:34:56" {
		t.Errorf("expected MAC b8:27:eb:12:34:56, got %s", h.MACAddress)
	}
	if h.Hostname != "raspberrypi" {
		t.Errorf("expected hostname raspberrypi, got %s", h.Hostname)
	}
	if !h.IsDHCP {
		t.Errorf("expected IsDHCP to be true, got false")
	}
	if h.Status != "up" {
		t.Errorf("expected Status up, got %s", h.Status)
	}
	if h.OSVendor != "Linux" {
		t.Errorf("expected OS Linux, got %s", h.OSVendor)
	}
	if h.SegmentID == nil || *h.SegmentID != seg.ID {
		t.Errorf("expected SegmentID %d, got %v", seg.ID, h.SegmentID)
	}
	if h.VendorModel == "" {
		t.Errorf("expected VendorModel to be resolved from OUI, got empty")
	}
}
