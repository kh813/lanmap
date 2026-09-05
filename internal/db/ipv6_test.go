package db

import (
	"testing"
)

func TestClassifyIPv6(t *testing.T) {
	tests := []struct {
		addr     string
		wantType IPv6Type
	}{
		{"fe80::1ff:fe00:1", IPv6TypeLLA},
		{"fe80::1%en0", IPv6TypeLLA},
		{"2001:db8::1", IPv6TypeGUA},
		{"2400:cb00:2048:1::c629:d7a2", IPv6TypeGUA},
		{"fc00::1", IPv6TypeULA},
		{"fd12:3456:789a::1", IPv6TypeULA},
		{"::1", IPv6TypeOther}, // Loopback
		{"192.168.1.1", IPv6TypeOther},
	}

	for _, tc := range tests {
		info := ClassifyIPv6(tc.addr)
		if info.Type != tc.wantType {
			t.Errorf("ClassifyIPv6(%q) type = %s; want %s", tc.addr, info.Type, tc.wantType)
		}
	}
}

func TestMergeIPv6Addresses(t *testing.T) {
	merged := mergeIPv6Addresses(
		"fe80::1",
		"2001:db8::1, fe80::1",
		"fd00::1234",
		"fe80::1%en0",
	)

	// Should deduplicate fe80::1, sort GUA (2001:db8::1), ULA (fd00::1234), LLA (fe80::1)
	expected := "2001:db8::1, fd00::1234, fe80::1"
	if merged != expected {
		t.Errorf("mergeIPv6Addresses() = %q; want %q", merged, expected)
	}
}

func TestIPVersionSettings(t *testing.T) {
	database := setupTestDB(t)

	// Default values
	v4, v6, err := database.GetIPVersionSettings()
	if err != nil {
		t.Fatalf("GetIPVersionSettings failed: %v", err)
	}
	if !v4 || v6 {
		t.Errorf("default IP version settings = (v4=%v, v6=%v); want (true, false)", v4, v6)
	}

	// Enable both
	if err := database.SetIPVersionSettings(true, true); err != nil {
		t.Fatalf("SetIPVersionSettings(true, true) failed: %v", err)
	}
	v4, v6, _ = database.GetIPVersionSettings()
	if !v4 || !v6 {
		t.Errorf("settings = (v4=%v, v6=%v); want (true, true)", v4, v6)
	}

	// Disable IPv4 (IPv6 only)
	if err := database.SetIPVersionSettings(false, true); err != nil {
		t.Fatalf("SetIPVersionSettings(false, true) failed: %v", err)
	}
	v4, v6, _ = database.GetIPVersionSettings()
	if v4 || !v6 {
		t.Errorf("settings = (v4=%v, v6=%v); want (false, true)", v4, v6)
	}

	// Disabling both must be rejected
	if err := database.SetIPVersionSettings(false, false); err == nil {
		t.Errorf("expected error when setting both IPv4 and IPv6 to false, got nil")
	}
}

func TestDualStackHostUpsert(t *testing.T) {
	database := setupTestDB(t)

	mac := "00:11:22:33:44:55"
	ipv4 := "192.168.1.50"
	lla := "fe80::211:22ff:fe33:4455"
	gua := "2001:db8::50"

	// 1. First discovered via IPv4
	h1 := &Host{
		IP:         ipv4,
		MACAddress: mac,
		Hostname:   "dual-device",
		Status:     "up",
	}
	isNew, _, err := database.UpsertHostOnScan(h1)
	if err != nil || !isNew {
		t.Fatalf("failed to insert IPv4 host: %v", err)
	}

	fetched1, err := database.GetHost(ipv4)
	if err != nil || fetched1 == nil {
		t.Fatalf("failed to fetch host by IPv4: %v", err)
	}
	if fetched1.HasIPv6() {
		t.Errorf("expected HasIPv6=false initially, got true")
	}

	// 2. Discovered via IPv6 scan (LLA + GUA) with the same MAC
	h2 := &Host{
		IP:            lla,
		MACAddress:    mac,
		IPv6Addresses: gua,
		Status:        "up",
	}
	isNew, _, err = database.UpsertHostOnScan(h2)
	if err != nil {
		t.Fatalf("failed to upsert IPv6 for existing host: %v", err)
	}
	if isNew {
		t.Errorf("expected existing host to be updated, but was treated as new")
	}

	// Fetch by IPv4: Primary IP must remain IPv4, and IPv6Addresses must contain GUA and LLA
	fetched2, err := database.GetHost(ipv4)
	if err != nil || fetched2 == nil {
		t.Fatalf("failed to fetch host by IPv4 after IPv6 scan: %v", err)
	}
	if fetched2.IP != ipv4 {
		t.Errorf("primary IP = %s; want %s", fetched2.IP, ipv4)
	}
	if !fetched2.HasIPv6() {
		t.Errorf("expected HasIPv6=true")
	}

	v6List := fetched2.GetIPv6List()
	if len(v6List) != 2 {
		t.Fatalf("expected 2 IPv6 addresses, got %d (%+v)", len(v6List), fetched2.IPv6Addresses)
	}

	// 3. Search by IPv6 address directly via GetHost
	foundByLLA, err := database.GetHost(lla)
	if err != nil || foundByLLA == nil {
		t.Fatalf("failed to find host by LLA: %v", err)
	}
	if foundByLLA.ID != fetched2.ID {
		t.Errorf("found host ID = %d; want %d", foundByLLA.ID, fetched2.ID)
	}

	foundByGUA, err := database.GetHost(gua)
	if err != nil || foundByGUA == nil {
		t.Fatalf("failed to find host by GUA: %v", err)
	}
	if foundByGUA.ID != fetched2.ID {
		t.Errorf("found host ID = %d; want %d", foundByGUA.ID, fetched2.ID)
	}

	// 4. Pure IPv6 host test (no IPv4 discovered)
	pureV6MAC := "00:AA:BB:CC:DD:EE"
	pureV6IP := "fe80::100"
	hPure := &Host{
		IP:         pureV6IP,
		MACAddress: pureV6MAC,
		Hostname:   "pure-v6-device",
		Status:     "up",
	}
	isNew, _, err = database.UpsertHostOnScan(hPure)
	if err != nil || !isNew {
		t.Fatalf("failed to insert pure IPv6 host: %v", err)
	}

	fetchedPure, err := database.GetHost(pureV6IP)
	if err != nil || fetchedPure == nil {
		t.Fatalf("failed to fetch pure IPv6 host: %v", err)
	}
	if !fetchedPure.IsPureIPv6() {
		t.Errorf("expected IsPureIPv6=true for pure IPv6 host")
	}

	// Now an IPv4 address is assigned to pure-v6-device
	newIPv4 := "192.168.1.188"
	hPureWithV4 := &Host{
		IP:         newIPv4,
		MACAddress: pureV6MAC,
		Status:     "up",
	}
	_, _, err = database.UpsertHostOnScan(hPureWithV4)
	if err != nil {
		t.Fatalf("failed to update pure IPv6 host with IPv4: %v", err)
	}

	fetchedUpgraded, err := database.GetHost(newIPv4)
	if err != nil || fetchedUpgraded == nil {
		t.Fatalf("failed to fetch upgraded host by new IPv4: %v", err)
	}
	if fetchedUpgraded.IP != newIPv4 {
		t.Errorf("primary IP = %s; want %s", fetchedUpgraded.IP, newIPv4)
	}
	if !fetchedUpgraded.HasIPv6() {
		t.Errorf("expected HasIPv6=true after upgrade to dual-stack")
	}
}
