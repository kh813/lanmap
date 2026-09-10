package scanner

import (
	"net"
	"strings"
)

// IsVLANInterface checks if an interface name is a Tagged VLAN (IEEE 802.1Q) sub-interface.
// Typical patterns:
// - Linux: eth0.10, enp3s0.100, vlan10, vlan.10
// - macOS: vlan0, vlan1, en0.10
func IsVLANInterface(iface string) bool {
	lower := strings.ToLower(strings.TrimSpace(iface))
	if lower == "" {
		return false
	}
	// Dot notation indicating sub-interface (e.g., eth0.10, en0.20)
	if strings.Contains(lower, ".") {
		return true
	}
	// Prefix vlan (e.g., vlan0, vlan1, vlan10)
	if strings.HasPrefix(lower, "vlan") {
		return true
	}
	return false
}

// IsVLANContext checks if either the network interface name or segment name signifies a VLAN environment.
// For example, an interface named "vlan1", "en0.1", or a segment named "VLAN 1", "Guest VLAN".
func IsVLANContext(iface, segmentName string) bool {
	if IsVLANInterface(iface) {
		return true
	}
	segLower := strings.ToLower(strings.TrimSpace(segmentName))
	return strings.Contains(segLower, "vlan")
}

// GetLocalMACAddresses returns a set of normalized MAC addresses belonging to the local machine.
// This prevents the host machine's own interfaces from ever being flagged as rogue routers or unapproved devices.
func GetLocalMACAddresses() map[string]bool {
	macs := make(map[string]bool)
	ifaces, err := net.Interfaces()
	if err != nil {
		return macs
	}

	for _, iface := range ifaces {
		if len(iface.HardwareAddr) == 0 {
			continue
		}
		norm := NormalizeMAC(iface.HardwareAddr.String())
		if norm != "" {
			macs[norm] = true
		}
	}
	return macs
}
