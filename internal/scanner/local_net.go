package scanner

import (
	"fmt"
	"net"
	"strings"
)

// DetectedNetwork holds info about an active local network interface
type DetectedNetwork struct {
	Name      string
	CIDR      string
	IP        string
	IsDefault bool // True if this interface is attached to the default gateway (default route)
}

// GetDefaultGatewayLocalIP resolves the outbound local IP used for default gateway
func GetDefaultGatewayLocalIP() net.IP {
	// Attempt outbound UDP route resolution to internet DNS (no actual packet is transmitted)
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{
		IP:   net.IPv4(8, 8, 8, 8),
		Port: 53,
	})
	if err != nil {
		conn, err = net.DialUDP("udp", nil, &net.UDPAddr{
			IP:   net.IPv4(1, 1, 1, 1),
			Port: 53,
		})
		if err != nil {
			return nil
		}
	}
	defer conn.Close()

	if localAddr, ok := conn.LocalAddr().(*net.UDPAddr); ok {
		return localAddr.IP.To4()
	}
	return nil
}

// DetectLocalNetworks discovers active IPv4 private network interfaces
func DetectLocalNetworks() ([]DetectedNetwork, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	defaultIP := GetDefaultGatewayLocalIP()

	var networks []DetectedNetwork
	hasDefault := false

	for _, iface := range ifaces {
		// Skip down or loopback interfaces
		if (iface.Flags&net.FlagUp) == 0 || (iface.Flags&net.FlagLoopback) != 0 {
			continue
		}
		// Skip low-level container veth pairs or tun devices
		if strings.HasPrefix(iface.Name, "utun") || strings.HasPrefix(iface.Name, "veth") {
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

				isDef := false
				if defaultIP != nil && ipv4.Equal(defaultIP) {
					isDef = true
					hasDefault = true
				}

				networks = append(networks, DetectedNetwork{
					Name:      iface.Name,
					CIDR:      cidr,
					IP:        ipv4.String(),
					IsDefault: isDef,
				})
			}
		}
	}

	// Fallback: If no default gateway was detected, mark the first network as default
	if !hasDefault && len(networks) > 0 {
		networks[0].IsDefault = true
	}

	return networks, nil
}

// GetDefaultInterface returns the primary network interface used for the default route
func GetDefaultInterface() (*net.Interface, error) {
	networks, err := DetectLocalNetworks()
	if err != nil || len(networks) == 0 {
		return nil, fmt.Errorf("no active network interfaces found")
	}
	for _, n := range networks {
		if n.IsDefault {
			return net.InterfaceByName(n.Name)
		}
	}
	return net.InterfaceByName(networks[0].Name)
}
