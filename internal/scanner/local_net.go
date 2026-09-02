package scanner

import (
	"fmt"
	"net"
	"strings"
)

// DetectedNetwork holds info about an active local network interface
type DetectedNetwork struct {
	Name string
	CIDR string
	IP   string
}

// DetectLocalNetworks discovers active IPv4 private network interfaces
func DetectLocalNetworks() ([]DetectedNetwork, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	var networks []DetectedNetwork
	for _, iface := range ifaces {
		// Skip down, loopback, or virtual interfaces
		if (iface.Flags&net.FlagUp) == 0 || (iface.Flags&net.FlagLoopback) != 0 {
			continue
		}
		if strings.HasPrefix(iface.Name, "utun") || strings.HasPrefix(iface.Name, "docker") || strings.HasPrefix(iface.Name, "veth") {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}
			ipv4 := ipNet.IP.To4()
			if ipv4 == nil || ipv4.IsLoopback() || ipv4.IsLinkLocalUnicast() {
				continue
			}

			mask := ipNet.Mask
			ones, bits := mask.Size()
			if bits == 32 && ones >= 16 && ones <= 30 {
				networkIP := ipv4.Mask(mask)
				cidr := fmt.Sprintf("%s/%d", networkIP.String(), ones)
				networks = append(networks, DetectedNetwork{
					Name: iface.Name,
					CIDR: cidr,
					IP:   ipv4.String(),
				})
			}
		}
	}

	return networks, nil
}
