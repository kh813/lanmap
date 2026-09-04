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
		22:   "SSH (リモートログイン)",
		80:   "HTTP",
		443:  "HTTPS",
		445:  "SMB (ファイル共有)",
		548:  "AFP (Mac共有)",
		5900: "VNC (画面共有)",
		5938: "TeamViewer",
		7070: "AnyDesk",
	},
	ProfileAppleMobile: {
		// Mobile Apple devices (iOS, watchOS) run in deep stealth; no open inbound TCP ports
	},
	ProfileWindows: {
		80:   "HTTP",
		443:  "HTTPS",
		445:  "SMB (ファイル共有)",
		1723: "PPTP VPN",
		3389: "RDP (リモートデスクトップ)",
		5555: "SoftEther VPN",
		5900: "VNC",
		5938: "TeamViewer",
		7070: "AnyDesk",
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
		1194: "OpenVPN",
		5000: "Synology DSM / UPnP",
		5001: "Synology DSM (HTTPS)",
		5555: "SoftEther VPN",
		5900: "VNC",
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
		1194: "OpenVPN",
		1723: "PPTP VPN",
		3389: "RDP (リモートデスクトップ)",
		5555: "SoftEther VPN",
		5900: "VNC",
		5938: "TeamViewer",
		7070: "AnyDesk",
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
// Prevents triggering IDS/firewalls (port scan warnings).
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

// FullScanPortMap defines an extensive list of well-known and common ports for Full Scan Mode
var FullScanPortMap = map[int]string{
	21:    "FTP",
	22:    "SSH",
	23:    "Telnet",
	25:    "SMTP",
	53:    "DNS",
	80:    "HTTP",
	110:   "POP3",
	135:   "MSRPC",
	139:   "NetBIOS-SSN",
	143:   "IMAP",
	443:   "HTTPS",
	445:   "SMB (ファイル共有)",
	548:   "AFP (Mac共有)",
	554:   "RTSP (カメラ)",
	631:   "IPP (プリンタ)",
	993:   "IMAPS",
	995:   "POP3S",
	1194:  "OpenVPN",
	1433:  "MSSQL",
	1521:  "Oracle DB",
	1723:  "PPTP VPN",
	3000:  "Node/Dev",
	3306:  "MySQL",
	3389:  "RDP (リモートデスクトップ)",
	5000:  "Synology DSM / UPnP",
	5001:  "Synology DSM (HTTPS)",
	5432:  "PostgreSQL",
	5555:  "SoftEther VPN",
	5900:  "VNC (画面共有)",
	5938:  "TeamViewer",
	6379:  "Redis",
	7070:  "AnyDesk",
	8000:  "HTTP-Dev",
	8008:  "Google Cast",
	8080:  "HTTP-Alt",
	8081:  "HTTP-Alt",
	8443:  "HTTPS-Alt",
	8888:  "HTTP-Alt",
	9000:  "PHP-FPM/Sonar",
	9100:  "RAW プリンタ",
	9200:  "Elasticsearch",
	27017: "MongoDB",
}

// ScanOpenPortsFull scans all ports in FullScanPortMap
func ScanOpenPortsFull(ip string, timeout time.Duration) string {
	if timeout <= 0 {
		timeout = 70 * time.Millisecond
	}

	type portResult struct {
		port    int
		service string
		open    bool
	}

	resChan := make(chan portResult, len(FullScanPortMap))
	var wg sync.WaitGroup

	for port, service := range FullScanPortMap {
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

// ScanOpenPortsLowNoise scans target ports serially with an intentional delay between ports (e.g. 100ms)
// and modest connection timeout. This spreads out packets so that personal firewalls
// never see burst RST packets or trigger port scan warnings.
func ScanOpenPortsLowNoise(ip string, profile DeviceProfile, timeout time.Duration, interPortDelay time.Duration) string {
	ports := GetTargetPortsForProfile(profile)
	if len(ports) == 0 {
		return ""
	}

	if timeout <= 0 {
		timeout = 60 * time.Millisecond
	}
	if interPortDelay <= 0 {
		interPortDelay = 100 * time.Millisecond
	}

	// Sort ports to scan deterministically
	var portList []int
	for p := range ports {
		portList = append(portList, p)
	}
	sort.Ints(portList)

	var openParts []string
	for i, p := range portList {
		if i > 0 {
			time.Sleep(interPortDelay)
		}
		addr := net.JoinHostPort(ip, fmt.Sprintf("%d", p))
		conn, err := net.DialTimeout("tcp", addr, timeout)
		if err == nil {
			conn.Close()
			openParts = append(openParts, fmt.Sprintf("%d:%s", p, ports[p]))
		}
	}

	return strings.Join(openParts, ",")
}

type PortRiskLevel string

const (
	RiskCritical PortRiskLevel = "critical" // 🚨 VPN サーバー検知
	RiskWarning  PortRiskLevel = "warning"  // ⚠️ リモートアクセス待受
	RiskInfo     PortRiskLevel = "info"     // ℹ️ 一般サービス
)

type PortRiskInfo struct {
	Port        int
	Service     string
	Level       PortRiskLevel
	Category    string // "VPN", "RemoteAccess", "RemoteLogin", "Normal"
	BadgeClass  string
	Description string
}

// EvaluatePortRisk classifies an open port into a security risk level
func EvaluatePortRisk(port int, service string) PortRiskInfo {
	switch port {
	case 1194, 1723, 5555:
		return PortRiskInfo{
			Port:        port,
			Service:     service,
			Level:       RiskCritical,
			Category:    "VPN",
			BadgeClass:  "bg-rose-100 text-rose-800 border-rose-300 dark:bg-rose-950/70 dark:text-rose-300 dark:border-rose-800",
			Description: "🚨 VPNサーバー待受",
		}
	case 3389, 5900, 5938, 7070:
		return PortRiskInfo{
			Port:        port,
			Service:     service,
			Level:       RiskWarning,
			Category:    "RemoteAccess",
			BadgeClass:  "bg-amber-100 text-amber-800 border-amber-300 dark:bg-amber-950/70 dark:text-amber-300 dark:border-amber-800",
			Description: "⚠️ リモートアクセス待受",
		}
	case 22, 23:
		return PortRiskInfo{
			Port:        port,
			Service:     service,
			Level:       RiskWarning,
			Category:    "RemoteLogin",
			BadgeClass:  "bg-orange-100 text-orange-800 border-orange-300 dark:bg-orange-950/70 dark:text-orange-300 dark:border-orange-800",
			Description: "⚠️ リモートログイン待受",
		}
	default:
		return PortRiskInfo{
			Port:        port,
			Service:     service,
			Level:       RiskInfo,
			Category:    "Normal",
			BadgeClass:  "bg-blue-50 text-blue-700 border-blue-200 dark:bg-blue-950/60 dark:text-blue-300 dark:border-blue-800",
			Description: "一般サービス",
		}
	}
}

