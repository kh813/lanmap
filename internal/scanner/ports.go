package scanner

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

type DeviceProfile string

const (
	ProfileAppleMac    DeviceProfile = "apple_mac"
	ProfileAppleMobile DeviceProfile = "apple_mobile"
	ProfileWindows     DeviceProfile = "windows"
	ProfilePrinter     DeviceProfile = "printer"
	ProfileNetwork     DeviceProfile = "network"
	ProfileNASLinux    DeviceProfile = "nas_linux"
	ProfileMediaIoT    DeviceProfile = "media_iot"
	ProfileGeneric     DeviceProfile = "generic"
)

var profilePortMaps = map[DeviceProfile]map[int]string{
	ProfileAppleMac: {
		80:   "HTTP",
		443:  "HTTPS",
		445:  "SMB (ファイル共有)",
		548:  "AFP (Mac共有)",
		5000: "AirPlay (macOS)",
		7000: "AirPlay",
	},
	ProfileAppleMobile: {
		// Mobile Apple devices (iOS, watchOS) run in deep stealth; no open inbound TCP ports
	},
	ProfileWindows: {
		80:   "HTTP",
		443:  "HTTPS",
		445:  "SMB (ファイル共有)",
		3389: "RDP (リモートデスクトップ)",
	},
	ProfilePrinter: {
		80:   "HTTP (管理画面)",
		443:  "HTTPS (管理画面)",
		631:  "IPP (プリンタ)",
		9100: "RAW プリンタ",
	},
	ProfileNetwork: {
		22:   "SSH",
		53:   "DNS",
		80:   "HTTP",
		443:  "HTTPS",
		8080: "HTTP-Alt",
		8443: "HTTPS-Alt",
	},
	ProfileNASLinux: {
		22:   "SSH",
		80:   "HTTP",
		443:  "HTTPS",
		445:  "SMB (ファイル共有)",
		5000: "Synology DSM / UPnP",
		5001: "Synology DSM (HTTPS)",
		8080: "HTTP-Alt",
		8443: "HTTPS-Alt",
	},
	ProfileMediaIoT: {
		80:   "HTTP",
		443:  "HTTPS",
		554:  "RTSP (カメラ)",
		8008: "Google Cast",
	},
	ProfileGeneric: {
		22:   "SSH",
		80:   "HTTP",
		443:  "HTTPS",
		445:  "SMB (ファイル共有)",
	},
}

// DetermineDeviceProfile infers device category from vendor, osVendor, hostname, and TTL
func DetermineDeviceProfile(vendor, osVendor, hostname string, ttl int) DeviceProfile {
	combined := strings.ToLower(fmt.Sprintf("%s %s %s", vendor, osVendor, hostname))

	// 1. Printers (Very distinct OUI & hostnames)
	if strings.Contains(combined, "canon") ||
		strings.Contains(combined, "epson") ||
		strings.Contains(combined, "brother") ||
		strings.Contains(combined, "ricoh") ||
		strings.Contains(combined, "fuji xerox") ||
		strings.Contains(combined, "fujifilm") ||
		strings.Contains(combined, "kyocera") ||
		strings.Contains(combined, "konica") ||
		strings.Contains(combined, "hp print") ||
		strings.Contains(combined, "laserjet") ||
		strings.Contains(combined, "deskjet") ||
		strings.Contains(combined, "printer") {
		return ProfilePrinter
	}

	// 2. Apple Devices
	if strings.Contains(combined, "apple") || strings.Contains(combined, "mac") || strings.Contains(combined, "ios") || strings.Contains(combined, "iphone") || strings.Contains(combined, "ipad") {
		if strings.Contains(combined, "iphone") ||
			strings.Contains(combined, "ipad") ||
			strings.Contains(combined, "watch") ||
			strings.Contains(combined, "homepod") ||
			strings.Contains(combined, "apple tv") ||
			strings.Contains(combined, "ios") {
			return ProfileAppleMobile
		}
		return ProfileAppleMac
	}

	// 3. Windows PC / Server (TTL 128 or explicit OS/hostname)
	if strings.Contains(combined, "windows") || strings.Contains(combined, "win10") || strings.Contains(combined, "win11") || strings.Contains(combined, "msft") || (ttl >= 100 && ttl <= 128) {
		return ProfileWindows
	}

	// 4. Network / Infrastructure Devices
	if strings.Contains(combined, "buffalo") ||
		strings.Contains(combined, "netgear") ||
		strings.Contains(combined, "cisco") ||
		strings.Contains(combined, "yamaha") ||
		strings.Contains(combined, "openwrt") ||
		strings.Contains(combined, "allied") ||
		strings.Contains(combined, "fortinet") ||
		strings.Contains(combined, "mikrotik") ||
		strings.Contains(combined, "aruba") ||
		strings.Contains(combined, "unifi") ||
		strings.Contains(combined, "ubiquiti") ||
		strings.Contains(combined, "router") ||
		strings.Contains(combined, "access point") ||
		strings.Contains(combined, "switch") ||
		ttl >= 200 {
		return ProfileNetwork
	}

	// 5. NAS / Dedicated Linux Storage & Servers
	if strings.Contains(combined, "synology") ||
		strings.Contains(combined, "qnap") ||
		strings.Contains(combined, "truenas") ||
		strings.Contains(combined, "freenas") ||
		strings.Contains(combined, "proxmox") ||
		strings.Contains(combined, "esxi") ||
		strings.Contains(combined, "server") ||
		strings.Contains(combined, "nas") ||
		strings.Contains(combined, "samba") {
		return ProfileNASLinux
	}

	// 6. Media / IoT / Cameras
	if strings.Contains(combined, "google") ||
		strings.Contains(combined, "chromecast") ||
		strings.Contains(combined, "nest") ||
		strings.Contains(combined, "echo") ||
		strings.Contains(combined, "alexa") ||
		strings.Contains(combined, "camera") ||
		strings.Contains(combined, "tv") {
		return ProfileMediaIoT
	}

	// 7. General Linux (TTL 64)
	if ttl == 64 || strings.Contains(combined, "linux") || strings.Contains(combined, "ubuntu") || strings.Contains(combined, "debian") {
		return ProfileNASLinux
	}

	return ProfileGeneric
}

// GetTargetPortsForProfile returns specific relevant ports for the device profile
func GetTargetPortsForProfile(profile DeviceProfile) map[int]string {
	if ports, ok := profilePortMaps[profile]; ok {
		return ports
	}
	return profilePortMaps[ProfileGeneric]
}

// ScanOpenPortsForProfile safely probes only relevant ports tailored to the device profile.
// Prevents triggering IDS/firewalls like ESET Port Scan Attack warnings.
func ScanOpenPortsForProfile(ip string, profile DeviceProfile, timeout time.Duration) string {
	ports := GetTargetPortsForProfile(profile)
	if len(ports) == 0 {
		return ""
	}

	if timeout <= 0 {
		timeout = 60 * time.Millisecond
	}

	type portResult struct {
		port    int
		service string
		open    bool
	}

	resChan := make(chan portResult, len(ports))
	var wg sync.WaitGroup

	for port, service := range ports {
		wg.Add(1)
		go func(p int, s string) {
			defer wg.Done()
			addr := net.JoinHostPort(ip, fmt.Sprintf("%d", p))
			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err == nil {
				conn.Close()
				resChan <- portResult{port: p, service: s, open: true}
			} else {
				resChan <- portResult{port: p, service: s, open: false}
			}
		}(port, service)
	}

	wg.Wait()
	close(resChan)

	var openPorts []portResult
	for r := range resChan {
		if r.open {
			openPorts = append(openPorts, r)
		}
	}

	// Sort by port number ascending
	sort.Slice(openPorts, func(i, j int) bool {
		return openPorts[i].port < openPorts[j].port
	})

	var parts []string
	for _, op := range openPorts {
		parts = append(parts, fmt.Sprintf("%d:%s", op.port, op.service))
	}

	return strings.Join(parts, ",")
}

// ScanOpenPorts probes ports using generic profile for backwards compatibility
func ScanOpenPorts(ip string, timeout time.Duration) string {
	return ScanOpenPortsForProfile(ip, ProfileGeneric, timeout)
}

