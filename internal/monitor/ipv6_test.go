package monitor

import (
	"context"
	"encoding/binary"
	"net"
	"path/filepath"
	"testing"
	"time"

	"lanmap/internal/db"
	"lanmap/internal/notifier"
	"lanmap/internal/scanner"
)

func TestParseDHCPv6Packet(t *testing.T) {
	// Construct synthetic DHCPv6 Request packet
	var buf []byte

	// Header: MsgType=1 (Solicit), XID=0x123456
	buf = append(buf, 1, 0x12, 0x34, 0x56)

	// Option 1: Client ID with DUID-LL (type 3, ethernet hw 1, mac 00:11:22:33:44:55)
	opt1 := make([]byte, 4+10)
	binary.BigEndian.PutUint16(opt1[0:2], 1)  // code = 1
	binary.BigEndian.PutUint16(opt1[2:4], 10) // len = 10
	binary.BigEndian.PutUint16(opt1[4:6], 3)  // DUID-LL
	binary.BigEndian.PutUint16(opt1[6:8], 1)  // Ethernet
	copy(opt1[8:14], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	buf = append(buf, opt1...)

	// Option 3: IA_NA with sub-option 5 IAADDR (2001:db8::1234)
	iaAddr := net.ParseIP("2001:db8::1234")
	subOpt := make([]byte, 4+24)
	binary.BigEndian.PutUint16(subOpt[0:2], 5)  // code = 5 (IAADDR)
	binary.BigEndian.PutUint16(subOpt[2:4], 24) // len = 24
	copy(subOpt[4:20], iaAddr.To16())
	binary.BigEndian.PutUint32(subOpt[20:24], 3600)
	binary.BigEndian.PutUint32(subOpt[24:28], 7200)

	opt3Len := 12 + len(subOpt)
	opt3 := make([]byte, 4+12)
	binary.BigEndian.PutUint16(opt3[0:2], 3)
	binary.BigEndian.PutUint16(opt3[2:4], uint16(opt3Len))
	// IAID, T1, T2
	copy(opt3[4:16], make([]byte, 12))
	buf = append(buf, opt3...)
	buf = append(buf, subOpt...)

	// Option 39: FQDN ("my-host.lan")
	fqdnData := []byte{0x00, 0x07, 'm', 'y', '-', 'h', 'o', 's', 't', 0x03, 'l', 'a', 'n', 0x00}
	opt39 := make([]byte, 4)
	binary.BigEndian.PutUint16(opt39[0:2], 39)
	binary.BigEndian.PutUint16(opt39[2:4], uint16(len(fqdnData)))
	buf = append(buf, opt39...)
	buf = append(buf, fqdnData...)

	pkt, err := ParseDHCPv6Packet(buf)
	if err != nil {
		t.Fatalf("ParseDHCPv6Packet failed: %v", err)
	}

	if pkt.MessageType != 1 {
		t.Errorf("MessageType = %d; want 1", pkt.MessageType)
	}
	if pkt.ClientMAC != "00:11:22:33:44:55" {
		t.Errorf("ClientMAC = %s; want 00:11:22:33:44:55", pkt.ClientMAC)
	}
	if pkt.AssignedIP == nil || !pkt.AssignedIP.Equal(iaAddr) {
		t.Errorf("AssignedIP = %v; want %v", pkt.AssignedIP, iaAddr)
	}
	if pkt.Hostname != "my-host.lan" {
		t.Errorf("Hostname = %s; want my-host.lan", pkt.Hostname)
	}
}

func TestAuditRogueRouters_VLANvsNative(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_ipv6_audit.db")
	database, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("Open DB failed: %v", err)
	}
	defer database.Close()

	// 1. Setup segments:
	// - eth0: Native LAN (monitored)
	// - eth0.10: Tagged VLAN (unmonitored / disabled)
	// - vlan20: Tagged VLAN (monitored / enabled)
	_, _ = database.CreateSegment("Office Native LAN", "192.168.1.0/24", "eth0", true)
	_, _ = database.CreateSegment("Guest VLAN", "192.168.10.0/24", "eth0.10", false) // unmonitored
	_, _ = database.CreateSegment("IoT VLAN", "192.168.20.0/24", "vlan20", true)      // monitored

	notif := notifier.NewNotifier(database)
	m := NewIPv6Monitor(database, notif)
	ctx := context.Background()

	// Get local machine MACs to test self-exclusion
	localMACs := scanner.GetLocalMACAddresses()
	var selfMAC string
	for mac := range localMACs {
		selfMAC = mac
		break
	}

	entries := []scanner.NeighborEntry{
		// 1. Router on unmonitored Tagged VLAN -> should be completely ignored (no rogue alert, no vlan alert)
		{
			IP:        "fe80::10",
			MAC:       "00:11:22:33:44:01",
			Interface: "eth0.10",
			IsRouter:  true,
		},
		// 2. Unapproved Router on monitored Tagged VLAN -> should trigger VLAN notice, NOT rogue RA
		{
			IP:        "fe80::20",
			MAC:       "00:11:22:33:44:02",
			Interface: "vlan20",
			IsRouter:  true,
		},
		// 3. Unapproved Router on Native LAN -> should trigger high-severity Rogue RA alert
		{
			IP:        "fe80::30",
			MAC:       "00:11:22:33:44:03",
			Interface: "eth0",
			IsRouter:  true,
		},
	}

	if selfMAC != "" {
		// 4. Local machine own MAC on native LAN -> should be ignored
		entries = append(entries, scanner.NeighborEntry{
			IP:        "fe80::self",
			MAC:       selfMAC,
			Interface: "eth0",
			IsRouter:  true,
		})
	}

	m.AuditRogueRoutersWithEntries(ctx, entries)

	// Verify Entry 1 (Unmonitored VLAN): No alerts
	if _, ok := m.rogueAlerts["00:11:22:33:44:01"]; ok {
		t.Errorf("Expected router on unmonitored VLAN eth0.10 to NOT trigger rogue alert")
	}
	if _, ok := m.vlanAlerts["eth0.10@00:11:22:33:44:01"]; ok {
		t.Errorf("Expected router on unmonitored VLAN eth0.10 to NOT trigger vlan alert")
	}

	// Verify Entry 2 (Monitored VLAN): Should be in vlanAlerts, NOT in rogueAlerts
	if _, ok := m.rogueAlerts["00:11:22:33:44:02"]; ok {
		t.Errorf("Expected router on monitored VLAN vlan20 to NOT trigger high-severity rogue RA alert")
	}
	if _, ok := m.vlanAlerts["vlan20@00:11:22:33:44:02"]; !ok {
		t.Errorf("Expected router on monitored VLAN vlan20 to trigger vlan alert notice")
	}

	// Verify Entry 3 (Native LAN): Should be in rogueAlerts
	if _, ok := m.rogueAlerts["00:11:22:33:44:03"]; !ok {
		t.Errorf("Expected unauthorized router on native LAN eth0 to trigger rogue RA alert")
	}

	// Verify Entry 4 (Self MAC): Should NOT trigger rogue alert
	if selfMAC != "" {
		if _, ok := m.rogueAlerts[selfMAC]; ok {
			t.Errorf("Expected local machine's own MAC %s to be excluded from rogue alerts", selfMAC)
		}
	}
}

func TestAuditRogueRouters_VLAN1_Environment(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_vlan1.db")
	database, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("Open DB failed: %v", err)
	}
	defer database.Close()

	// Environment: Tagged VLAN, VLAN ID 1
	// Case A: Interface name explicitly specifies VLAN 1 (e.g. en0.1 or vlan1)
	_, _ = database.CreateSegment("VLAN 1 (Tagged)", "192.168.3.0/24", "vlan1", true)

	notif := notifier.NewNotifier(database)
	m := NewIPv6Monitor(database, notif)
	ctx := context.Background()

	routerMAC := "38:97:a4:4f:84:60"
	routerIP := "fe80::3a97:a4ff:fe4f:8460"

	entries := []scanner.NeighborEntry{
		{
			IP:        routerIP,
			MAC:       routerMAC,
			Interface: "vlan1",
			IsRouter:  true,
		},
	}

	// 1. Initial detection: router is unregistered in DB
	m.AuditRogueRoutersWithEntries(ctx, entries)

	// In a Tagged VLAN, an unregistered router MUST NOT trigger a high-severity Rogue RA alert!
	if _, ok := m.rogueAlerts[routerMAC]; ok {
		t.Errorf("FATAL: Router in Tagged VLAN 1 triggered Rogue RA alert! Expected relaxed notice instead.")
	}
	if _, ok := m.vlanAlerts["vlan1@"+routerMAC]; !ok {
		t.Errorf("Expected router in Tagged VLAN 1 to generate an informative VLAN Notice")
	}

	// 2. Administrator approves the router
	m.rogueAlerts = make(map[string]time.Time)
	m.vlanAlerts = make(map[string]time.Time)

	now := time.Now()
	_, _, err = database.UpsertHostOnScan(&db.Host{
		IP:          "192.168.3.1",
		MACAddress:  routerMAC,
		Hostname:    "openwrt.lan",
		IsApproved:  true,
		Status:      "up",
		FirstSeen:   now,
		LastSeen:    &now,
	})
	if err != nil {
		t.Fatalf("UpsertHostOnScan failed: %v", err)
	}

	m.AuditRogueRoutersWithEntries(ctx, entries)

	// Approved router must produce 0 alerts
	if len(m.rogueAlerts) > 0 {
		t.Errorf("Approved router triggered %d rogue alerts!", len(m.rogueAlerts))
	}
	if len(m.vlanAlerts) > 0 {
		t.Errorf("Approved router triggered %d vlan alerts!", len(m.vlanAlerts))
	}
}


