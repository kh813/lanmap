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
	ProfileVoIP        DeviceProfile = "voip"
	ProfileCamera      DeviceProfile = "camera"
	ProfileIoT         DeviceProfile = "iot"
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
		23:   "Telnet",
		53:   "DNS",
		80:   "HTTP",
		443:  "HTTPS",
		541:  "FortiTelemetry",
		8080: "HTTP-Alt",
		8443: "HTTPS-Alt",
	},
	ProfileNASLinux: {
		22:   "SSH",
		80:   "HTTP",
		443:  "HTTPS",
		445:  "SMB (ファイル共有)",
		1194: "OpenVPN",
		5000: "UPnP / AirPlay / Synology DSM",
		5001: "Synology DSM (HTTPS)",
		5555: "SoftEther VPN",
		5900: "VNC",
		8080: "HTTP-Alt",
		8443: "HTTPS-Alt",
	},
	ProfileVoIP: {
		80:   "HTTP (管理画面)",
		443:  "HTTPS (管理画面)",
		2000: "Cisco SCCP",
		5060: "SIP (VoIP)",
		5061: "SIPS (暗号化VoIP)",
		8080: "HTTP-Alt",
	},
	ProfileCamera: {
		80:    "HTTP (Webカメラ管理)",
		443:   "HTTPS (Webカメラ管理)",
		554:   "RTSP (映像配信)",
		8000:  "Hikvision 管理",
		8080:  "HTTP-Alt",
		8443:  "HTTPS-Alt",
		8899:  "ONVIF 探索",
		37777: "Dahua 管理",
	},
	ProfileIoT: {
		80:   "HTTP",
		443:  "HTTPS",
		1883: "MQTT (IoT)",
		8008: "Google Cast",
		8080: "HTTP-Alt",
		8883: "MQTTS (暗号化IoT)",
	},
	ProfileMediaIoT: {
		80:   "HTTP",
		443:  "HTTPS",
		554:  "RTSP (カメラ)",
		8008: "Google Cast",
		8080: "HTTP-Alt",
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

	// 2. IP Phones & VoIP (Yealink, Polycom, Cisco IP Phone, Grandstream, Snom, Fanvil)
	if strings.Contains(combined, "yealink") ||
		strings.Contains(combined, "polycom") ||
		strings.Contains(combined, "poly (") ||
		strings.Contains(combined, "grandstream") ||
		strings.Contains(combined, "snom") ||
		strings.Contains(combined, "fanvil") ||
		strings.Contains(combined, "ip phone") ||
		strings.Contains(combined, "voip") ||
		strings.Contains(combined, "sip-") ||
		strings.Contains(combined, "cisco ip phone") {
		return ProfileVoIP
	}

	// 3. IP Cameras & CCTV / Surveillance (Hikvision, Dahua, Axis, Hanwha, Panasonic Camera, Vivotek, Reolink)
	if strings.Contains(combined, "hikvision") ||
		strings.Contains(combined, "dahua") ||
		strings.Contains(combined, "axis communications") ||
		strings.Contains(combined, "hanwha") ||
		strings.Contains(combined, "techwin") ||
		strings.Contains(combined, "vivotek") ||
		strings.Contains(combined, "reolink") ||
		strings.Contains(combined, "uniview") ||
		strings.Contains(combined, "amcrest") ||
		strings.Contains(combined, "ipc-") ||
		strings.Contains(combined, "ipcam") ||
		strings.Contains(combined, "nvr") ||
		strings.Contains(combined, "dvr") ||
		strings.Contains(combined, "camera") {
		return ProfileCamera
	}

	// 4. Apple Devices
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

	// 5. Windows PC / Server (TTL 128 or explicit OS/hostname)
	if strings.Contains(combined, "windows") || strings.Contains(combined, "win10") || strings.Contains(combined, "win11") || strings.Contains(combined, "msft") || (ttl > 64 && ttl <= 128) {
		return ProfileWindows
	}

	// 6. Network / Infrastructure Devices (Fortinet, Aruba, Mist, Netgear, Cisco, Yamaha, Allied Telesis, Ubiquiti, etc.)
	if strings.Contains(combined, "fortinet") ||
		strings.Contains(combined, "fortigate") ||
		strings.Contains(combined, "aruba") ||
		strings.Contains(combined, "mist systems") ||
		strings.Contains(combined, "juniper") ||
		strings.Contains(combined, "netgear") ||
		strings.Contains(combined, "cisco") ||
		strings.Contains(combined, "yamaha") ||
		strings.Contains(combined, "allied telesis") ||
		strings.Contains(combined, "allied") ||
		strings.Contains(combined, "unifi") ||
		strings.Contains(combined, "ubiquiti") ||
		strings.Contains(combined, "mikrotik") ||
		strings.Contains(combined, "openwrt") ||
		strings.Contains(combined, "buffalo") ||
		strings.Contains(combined, "airstation") ||
		strings.Contains(combined, "nec") ||
		strings.Contains(combined, "aterm") ||
		strings.Contains(combined, "tp-link") ||
		strings.Contains(combined, "omada") ||
		strings.Contains(combined, "deco") ||
		strings.Contains(combined, "i-o data") ||
		strings.Contains(combined, "elecom") ||
		strings.Contains(combined, "router") ||
		strings.Contains(combined, "access point") ||
		strings.Contains(combined, "ap") ||
		strings.Contains(combined, "switch") ||
		ttl >= 200 {
		return ProfileNetwork
	}

	// 7. NAS / Dedicated Storage
	if strings.Contains(combined, "synology") ||
		strings.Contains(combined, "qnap") ||
		strings.Contains(combined, "asustor") ||
		strings.Contains(combined, "truenas") ||
		strings.Contains(combined, "freenas") ||
		strings.Contains(combined, "proxmox") ||
		strings.Contains(combined, "terastation") ||
		strings.Contains(combined, "linkstation") ||
		strings.Contains(combined, "esxi") ||
		strings.Contains(combined, "server") ||
		strings.Contains(combined, "nas") ||
		strings.Contains(combined, "samba") {
		return ProfileNASLinux
	}

	// 8. Media / IoT / Cast / TV
	if strings.Contains(combined, "google") ||
		strings.Contains(combined, "chromecast") ||
		strings.Contains(combined, "nest") ||
		strings.Contains(combined, "echo") ||
		strings.Contains(combined, "alexa") ||
		strings.Contains(combined, "tv") {
		return ProfileMediaIoT
	}

	// 9. IoT / Smart Home / Microcontrollers (SwitchBot, Nature Remo, ESP32, Tuya, Shelly, Hue)
	if strings.Contains(combined, "switchbot") ||
		strings.Contains(combined, "woan") ||
		strings.Contains(combined, "nature remo") ||
		strings.Contains(combined, "nature") ||
		strings.Contains(combined, "espressif") ||
		strings.Contains(combined, "esp32") ||
		strings.Contains(combined, "esp8266") ||
		strings.Contains(combined, "tuya") ||
		strings.Contains(combined, "shelly") ||
		strings.Contains(combined, "sonoff") ||
		strings.Contains(combined, "philips hue") ||
		strings.Contains(combined, "xiaomi") ||
		strings.Contains(combined, "aqara") {
		return ProfileIoT
	}

	// 10. General Linux (TTL 64)
	if ttl == 64 || strings.Contains(combined, "linux") || strings.Contains(combined, "ubuntu") || strings.Contains(combined, "debian") {
		return ProfileNASLinux
	}

	return ProfileGeneric
}

var (
	customPortResolverMu sync.RWMutex
	customPortResolver   func(profile DeviceProfile) (map[int]string, error)
)

// SetCustomPortResolver registers a dynamic custom port resolver (e.g. from database)
func SetCustomPortResolver(fn func(profile DeviceProfile) (map[int]string, error)) {
	customPortResolverMu.Lock()
	defer customPortResolverMu.Unlock()
	customPortResolver = fn
}

// GetTargetPortsForProfile returns specific relevant ports for the device profile
func GetTargetPortsForProfile(profile DeviceProfile) map[int]string {
	customPortResolverMu.RLock()
	resolver := customPortResolver
	customPortResolverMu.RUnlock()

	if resolver != nil {
		if ports, err := resolver(profile); err == nil && len(ports) > 0 {
			return ports
		}
	}

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
	88:    "Kerberos",
	110:   "POP3",
	135:   "MSRPC",
	139:   "NetBIOS-SSN",
	143:   "IMAP",
	389:   "LDAP",
	443:   "HTTPS",
	445:   "SMB (ファイル共有)",
	548:   "AFP (Mac共有)",
	293:   "IPP (プリンタ)",
	294:   "IPP (プリンタ)",
	295:   "LDAPS",
	296:   "IMAPS",
	297:   "POP3S",
	541:   "FortiTelemetry",
	554:   "RTSP (カメラ)",
	631:   "IPP (プリンタ)",
	636:   "LDAPS",
	993:   "IMAPS",
	995:   "POP3S",
	1194:  "OpenVPN",
	1433:  "MSSQL",
	1521:  "Oracle DB",
	1723:  "PPTP VPN",
	1883:  "MQTT (IoT)",
	2000:  "Cisco SCCP",
	3000:  "Node/Dev",
	3268:  "AD-GC",
	3306:  "MySQL",
	3389:  "RDP (リモートデスクトップ)",
	5000:  "UPnP / AirPlay / Synology DSM",
	5001:  "Synology DSM (HTTPS)",
	5060:  "SIP (VoIP)",
	5061:  "SIPS (VoIP)",
	5173:  "Vite/Dev",
	5432:  "PostgreSQL",
	5555:  "SoftEther VPN",
	5900:  "VNC (画面共有)",
	5938:  "TeamViewer",
	6379:  "Redis",
	7070:  "AnyDesk",
	8000:  "Hikvision/HTTP-Dev",
	8008:  "Google Cast",
	8080:  "HTTP-Alt",
	8081:  "HTTP-Alt",
	8443:  "HTTPS-Alt",
	8883:  "MQTTS (IoT)",
	8888:  "HTTP-Alt",
	8899:  "ONVIF (カメラ)",
	9000:  "PHP-FPM/Sonar",
	9100:  "RAW プリンタ",
	9200:  "Elasticsearch",
	27017: "MongoDB",
	37777: "Dahua 管理",
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
	case 1194, 1723, 5555, 5938, 7070:
		cat := "VPN"
		desc := "🚨 VPNサーバー待受"
		if port == 5938 {
			cat = "TeamViewer"
			desc = "🚨 TeamViewer 待受 (緊急)"
		} else if port == 7070 {
			cat = "AnyDesk"
			desc = "🚨 AnyDesk 待受 (緊急)"
		}
		return PortRiskInfo{
			Port:        port,
			Service:     service,
			Level:       RiskCritical,
			Category:    cat,
			BadgeClass:  "bg-rose-100 text-rose-800 border-rose-300 dark:bg-rose-950/70 dark:text-rose-300 dark:border-rose-800",
			Description: desc,
		}
	case 3389, 5900:
		return PortRiskInfo{
			Port:        port,
			Service:     service,
			Level:       RiskWarning,
			Category:    "RemoteAccess",
			BadgeClass:  "bg-amber-100 text-amber-800 border-amber-300 dark:bg-amber-950/70 dark:text-amber-300 dark:border-amber-800",
			Description: "⚠️ リモートアクセス待受",
		}
	case 23:
		return PortRiskInfo{
			Port:        port,
			Service:     service,
			Level:       RiskWarning,
			Category:    "RemoteLogin",
			BadgeClass:  "bg-orange-100 text-orange-800 border-orange-300 dark:bg-orange-950/70 dark:text-orange-300 dark:border-orange-800",
			Description: "⚠️ 平文リモートログイン待受 (Telnet)",
		}
	case 22:
		return PortRiskInfo{
			Port:        port,
			Service:     service,
			Level:       RiskInfo,
			Category:    "SSH",
			BadgeClass:  "bg-sky-50 text-sky-700 border-sky-200 dark:bg-sky-950/60 dark:text-sky-300 dark:border-sky-800",
			Description: "🔑 SSH (リモート保守管理)",
		}
	case 554, 8899, 37777:
		return PortRiskInfo{
			Port:        port,
			Service:     service,
			Level:       RiskInfo,
			Category:    "Camera",
			BadgeClass:  "bg-teal-50 text-teal-700 border-teal-200 dark:bg-teal-950/60 dark:text-teal-300 dark:border-teal-800",
			Description: "📹 監視カメラ / 映像配信ストリーム",
		}
	case 5060, 5061, 2000:
		return PortRiskInfo{
			Port:        port,
			Service:     service,
			Level:       RiskInfo,
			Category:    "VoIP",
			BadgeClass:  "bg-indigo-50 text-indigo-700 border-indigo-200 dark:bg-indigo-950/60 dark:text-indigo-300 dark:border-indigo-800",
			Description: "📞 IP電話 / VoIP (SIP)",
		}
	case 1883, 8883:
		return PortRiskInfo{
			Port:        port,
			Service:     service,
			Level:       RiskInfo,
			Category:    "IoT",
			BadgeClass:  "bg-emerald-50 text-emerald-700 border-emerald-200 dark:bg-emerald-950/60 dark:text-emerald-300 dark:border-emerald-800",
			Description: "🔌 IoT / スマート家電 (MQTT)",
		}
	case 541:
		return PortRiskInfo{
			Port:        port,
			Service:     service,
			Level:       RiskInfo,
			Category:    "Fortinet",
			BadgeClass:  "bg-purple-50 text-purple-700 border-purple-200 dark:bg-purple-950/60 dark:text-purple-300 dark:border-purple-800",
			Description: "🛡️ FortiGate Telemetry",
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

