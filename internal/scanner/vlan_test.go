package scanner

import (
	"testing"
)

func TestIsVLANInterface(t *testing.T) {
	tests := []struct {
		iface string
		want  bool
	}{
		{"eth0", false},
		{"en0", false},
		{"wlan0", false},
		{"lo", false},
		{"eth0.10", true},
		{"enp3s0.100", true},
		{"vlan0", true},
		{"vlan1", true},
		{"vlan10", true},
		{"vlan.20", true},
		{"VLAN50", true},
		{"en0.1", true},
		{"en0.5", true},
		{"", false},
	}

	for _, tt := range tests {
		got := IsVLANInterface(tt.iface)
		if got != tt.want {
			t.Errorf("IsVLANInterface(%q) = %v; want %v", tt.iface, got, tt.want)
		}
	}
}

func TestIsVLANContext(t *testing.T) {
	tests := []struct {
		iface   string
		segName string
		want    bool
	}{
		{"vlan1", "Default", true},
		{"en0.1", "Segment 1", true},
		{"en0", "VLAN 1 (Tagged)", true},
		{"en0", "Guest VLAN", true},
		{"eth0", "Corporate Network", false},
		{"en0", "ローカルLAN (en0)", false},
	}

	for _, tt := range tests {
		got := IsVLANContext(tt.iface, tt.segName)
		if got != tt.want {
			t.Errorf("IsVLANContext(%q, %q) = %v; want %v", tt.iface, tt.segName, got, tt.want)
		}
	}
}

func TestGetLocalMACAddresses(t *testing.T) {
	macs := GetLocalMACAddresses()
	// Local machine should have at least 1 network interface with MAC (e.g. en0)
	if len(macs) == 0 {
		t.Log("[INFO] No hardware MAC addresses returned (might be inside container/test env)")
	}
	for mac := range macs {
		norm := NormalizeMAC(mac)
		if norm != mac {
			t.Errorf("MAC %q was not normalized", mac)
		}
	}
}
