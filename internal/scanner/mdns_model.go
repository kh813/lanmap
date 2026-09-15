package scanner

import (
	"bytes"
	"fmt"
	"net"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// MDNSDeviceInfo holds detailed attributes extracted from mDNS/Bonjour _device-info queries
type MDNSDeviceInfo struct {
	RawModel   string // e.g. "MacBookPro18,4" or "Mac15,3"
	Model      string // e.g. "MacBook Pro (14-inch, M1 Max, 2021)"
	OSXVers    string // e.g. "24"
	MacOSVer   string // e.g. "macOS 15 Sequoia"
	DeviceName string // e.g. "Hiroshi’s MacBook Pro"
	IsApple    bool
}

var darwinToMacOSMap = map[string]string{
	"24": "macOS 15 Sequoia",
	"23": "macOS 14 Sonoma",
	"22": "macOS 13 Ventura",
	"21": "macOS 12 Monterey",
	"20": "macOS 11 Big Sur",
	"19": "macOS 10.15 Catalina",
	"18": "macOS 10.14 Mojave",
	"17": "macOS 10.13 High Sierra",
	"16": "macOS 10.12 Sierra",
	"15": "OS X 10.11 El Capitan",
	"14": "OS X 10.10 Yosemite",
}

var appleModelMap = map[string]string{
	// M4 series (2024)
	"Mac16,1":  "MacBook Pro (14-inch, M4, 2024)",
	"Mac16,2":  "iMac (24-inch, M4, 2-ports, 2024)",
	"Mac16,3":  "iMac (24-inch, M4, 4-ports, 2024)",
	"Mac16,5":  "MacBook Pro (16-inch, M4 Pro, 2024)",
	"Mac16,6":  "MacBook Pro (14-inch, M4 Pro, 2024)",
	"Mac16,7":  "MacBook Pro (16-inch, M4 Max, 2024)",
	"Mac16,8":  "MacBook Pro (14-inch, M4 Max, 2024)",
	"Mac16,10": "Mac mini (M4, 2024)",
	"Mac16,15": "Mac mini (M4 Pro, 2024)",

	// M3 series (2023 - 2024)
	"Mac15,3":  "MacBook Pro (14-inch, M3, Nov 2023)",
	"Mac15,4":  "iMac (24-inch, M3, 2-ports, 2023)",
	"Mac15,5":  "iMac (24-inch, M3, 4-ports, 2023)",
	"Mac15,6":  "MacBook Pro (14-inch, M3 Pro, Nov 2023)",
	"Mac15,7":  "MacBook Pro (16-inch, M3 Pro, Nov 2023)",
	"Mac15,8":  "MacBook Pro (14-inch, M3 Max, Nov 2023)",
	"Mac15,9":  "MacBook Pro (16-inch, M3 Max, Nov 2023)",
	"Mac15,10": "MacBook Pro (14-inch, M3 Pro, Nov 2023)",
	"Mac15,11": "MacBook Pro (16-inch, M3 Pro, Nov 2023)",
	"Mac15,12": "MacBook Air (13-inch, M3, 2024)",
	"Mac15,13": "MacBook Air (15-inch, M3, 2024)",

	// M2 series (2022 - 2023)
	"Mac14,2":  "MacBook Air (13-inch, M2, 2022)",
	"Mac14,3":  "Mac mini (M2, 2023)",
	"Mac14,5":  "MacBook Pro (14-inch, M2 Max, 2023)",
	"Mac14,6":  "MacBook Pro (16-inch, M2 Max, 2023)",
	"Mac14,7":  "MacBook Pro (13-inch, M2, 2022)",
	"Mac14,8":  "Mac Pro (M2 Ultra, 2023)",
	"Mac14,9":  "MacBook Pro (14-inch, M2 Pro, 2023)",
	"Mac14,10": "MacBook Pro (16-inch, M2 Pro, 2023)",
	"Mac14,12": "Mac mini (M2 Pro, 2023)",
	"Mac14,13": "Mac Studio (M2 Max, 2023)",
	"Mac14,14": "Mac Studio (M2 Ultra, 2023)",
	"Mac14,15": "MacBook Air (15-inch, M2, 2023)",

	// M1 series (2020 - 2022)
	"MacBookAir10,1": "MacBook Air (M1, 2020)",
	"MacBookPro17,1": "MacBook Pro (13-inch, M1, 2020)",
	"Macmini9,1":     "Mac mini (M1, 2020)",
	"iMac21,1":       "iMac (24-inch, M1, 2-ports, 2021)",
	"iMac21,2":       "iMac (24-inch, M1, 4-ports, 2021)",
	"Mac13,1":        "Mac Studio (M1 Max, 2022)",
	"Mac13,2":        "Mac Studio (M1 Ultra, 2022)",
	"MacBookPro18,1": "MacBook Pro (16-inch, 2021 M1 Pro)",
	"MacBookPro18,2": "MacBook Pro (16-inch, 2021 M1 Max)",
	"MacBookPro18,3": "MacBook Pro (14-inch, 2021 M1 Pro)",
	"MacBookPro18,4": "MacBook Pro (14-inch, 2021 M1 Max)",

	// Intel Macs (representative popular models)
	"MacBookPro16,1": "MacBook Pro (16-inch, 2019)",
	"MacBookPro16,2": "MacBook Pro (13-inch, 2020, 4 TB3 ports)",
	"MacBookPro16,3": "MacBook Pro (13-inch, 2020, 2 TB3 ports)",
	"MacBookPro15,1": "MacBook Pro (15-inch, 2018/2019)",
	"MacBookPro15,2": "MacBook Pro (13-inch, 2018/2019)",
	"MacBookPro14,1": "MacBook Pro (13-inch, 2017)",
	"MacBookPro14,3": "MacBook Pro (15-inch, 2017)",
	"MacBookAir9,1":  "MacBook Air (Retina 13-inch, 2020)",
	"MacBookAir8,1":  "MacBook Air (Retina 13-inch, 2018)",
	"MacBookAir8,2":  "MacBook Air (Retina 13-inch, 2019)",
	"Macmini8,1":     "Mac mini (2018)",
	"iMac20,1":       "iMac (Retina 5K, 27-inch, 2020)",
	"iMac20,2":       "iMac (Retina 5K, 27-inch, 2020)",
	"iMac19,1":       "iMac (Retina 5K, 27-inch, 2019)",
	"iMac19,2":       "iMac (Retina 4K, 21.5-inch, 2019)",
	"MacPro7,1":      "Mac Pro (2019)",

	// iPads
	"iPad11,1":  "iPad mini (5th Gen)",
	"iPad11,2":  "iPad mini (5th Gen Wi-Fi+Cellular)",
	"iPad11,6":  "iPad (8th Gen)",
	"iPad12,1":  "iPad (9th Gen)",
	"iPad13,1":  "iPad Air (4th Gen)",
	"iPad13,16": "iPad Air (5th Gen, M1)",
	"iPad13,18": "iPad (10th Gen)",
	"iPad13,19": "iPad (10th Gen Wi-Fi+Cellular)",
	"iPad14,1":  "iPad mini (6th Gen)",
	"iPad14,2":  "iPad mini (6th Gen Wi-Fi+Cellular)",
	"iPad14,3":  "iPad Pro 11-inch (4th Gen, M2)",
	"iPad14,4":  "iPad Pro 11-inch (4th Gen Wi-Fi+Cellular)",
	"iPad14,5":  "iPad Pro 12.9-inch (6th Gen, M2)",
	"iPad14,6":  "iPad Pro 12.9-inch (6th Gen Wi-Fi+Cellular)",
	"iPad14,8":  "iPad Air 11-inch (M2, 2024)",
	"iPad14,9":  "iPad Air 11-inch (M2, 2024 Wi-Fi+Cellular)",
	"iPad14,10": "iPad Air 13-inch (M2, 2024)",
	"iPad14,11": "iPad Air 13-inch (M2, 2024 Wi-Fi+Cellular)",
	"iPad16,1":  "iPad mini (A17 Pro, 2024)",
	"iPad16,2":  "iPad mini (A17 Pro, 2024 Wi-Fi+Cellular)",
	"iPad16,3":  "iPad Pro 11-inch (M4, 2024)",
	"iPad16,4":  "iPad Pro 11-inch (M4, 2024 Wi-Fi+Cellular)",
	"iPad16,5":  "iPad Pro 13-inch (M4, 2024)",
	"iPad16,6":  "iPad Pro 13-inch (M4, 2024 Wi-Fi+Cellular)",

	// iPhones
	"iPhone11,2": "iPhone XS",
	"iPhone11,4": "iPhone XS Max",
	"iPhone11,6": "iPhone XS Max",
	"iPhone11,8": "iPhone XR",
	"iPhone12,1": "iPhone 11",
	"iPhone12,3": "iPhone 11 Pro",
	"iPhone12,5": "iPhone 11 Pro Max",
	"iPhone12,8": "iPhone SE (2nd Gen)",
	"iPhone13,1": "iPhone 12 mini",
	"iPhone13,2": "iPhone 12",
	"iPhone13,3": "iPhone 12 Pro",
	"iPhone13,4": "iPhone 12 Pro Max",
	"iPhone14,2": "iPhone 13 Pro",
	"iPhone14,3": "iPhone 13 Pro Max",
	"iPhone14,4": "iPhone 13 mini",
	"iPhone14,5": "iPhone 13",
	"iPhone14,6": "iPhone SE (3rd Gen)",
	"iPhone14,7": "iPhone 14",
	"iPhone14,8": "iPhone 14 Plus",
	"iPhone15,2": "iPhone 14 Pro",
	"iPhone15,3": "iPhone 14 Pro Max",
	"iPhone15,4": "iPhone 15",
	"iPhone15,5": "iPhone 15 Plus",
	"iPhone16,1": "iPhone 15 Pro",
	"iPhone16,2": "iPhone 15 Pro Max",
	"iPhone17,1": "iPhone 16 Pro",
	"iPhone17,2": "iPhone 16 Pro Max",
	"iPhone17,3": "iPhone 16",
	"iPhone17,4": "iPhone 16 Plus",

	// Accessories & Home
	"AppleTV11,1":       "Apple TV 4K (2nd Gen)",
	"AppleTV14,1":       "Apple TV 4K (3rd Gen)",
	"AudioAccessory1,1": "HomePod",
	"AudioAccessory5,1": "HomePod mini",
	"AudioAccessory6,1": "HomePod (2nd Gen)",
}

// QueryMDNSDeviceInfo sends a unicast mDNS query to target IP:5353 to retrieve verified hardware model signature (e.g. MacBookPro18,4)
func QueryMDNSDeviceInfo(ipStr string, timeout time.Duration) string {
	info := QueryMDNSDeviceInfoFull(ipStr, timeout)
	return info.RawModel
}

// QueryMDNSDeviceInfoFull sends a unicast mDNS query to target IP:5353 and extracts model, osxvers, and friendly device name.
func QueryMDNSDeviceInfoFull(ipStr string, timeout time.Duration) MDNSDeviceInfo {
	var info MDNSDeviceInfo
	addr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(ipStr, "5353"))
	if err != nil {
		return info
	}
	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return info
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// DNS Query for _device-info._tcp.local (Type PTR = 12, Class IN = 1)
	query := []byte{
		0x00, 0x00, // ID
		0x00, 0x00, // Flags
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answer RRs
		0x00, 0x00, // Authority RRs
		0x00, 0x00, // Additional RRs
		0x0c, '_', 'd', 'e', 'v', 'i', 'c', 'e', '-', 'i', 'n', 'f', 'o',
		0x04, '_', 't', 'c', 'p',
		0x05, 'l', 'o', 'c', 'a', 'l',
		0x00,
		0x00, 0x0c, // Type: PTR
		0x80, 0x01, // Class: IN (Unicast response)
	}

	if _, err := conn.Write(query); err != nil {
		return info
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		return info
	}

	return ParseMDNSDeviceInfoPayload(buf[:n])
}

// ParseMDNSDeviceInfoPayload parses raw DNS response payload from _device-info._tcp.local
func ParseMDNSDeviceInfoPayload(buf []byte) MDNSDeviceInfo {
	var info MDNSDeviceInfo
	raw := string(buf)

	// 1. Extract model=...
	if rawModel := parseTXTField(raw, "model"); rawModel != "" {
		info.RawModel = rawModel
		info.Model = ResolveMDNSModel(rawModel)
		if isAppleModelSignature(rawModel) {
			info.IsApple = true
		}
	}

	// 2. Extract osxvers=...
	if osxvers := parseTXTField(raw, "osxvers"); osxvers != "" {
		info.OSXVers = osxvers
		info.MacOSVer = ResolveMacOSVersion(osxvers)
		info.IsApple = true
	}

	// 3. Extract Device / Instance Name from PTR record
	info.DeviceName = extractMDNSDeviceName(buf)

	return info
}

func parseTXTField(raw string, key string) string {
	target := key + "="
	idx := strings.Index(raw, target)
	if idx == -1 {
		return ""
	}
	part := raw[idx+len(target):]
	end := strings.IndexAny(part, "\x00\r\n\t ;\"<>\x01\x02\x03\x04\x05\x06\x07\x08\x09")
	if end != -1 {
		part = part[:end]
	}
	return strings.TrimSpace(part)
}

func extractMDNSDeviceName(buf []byte) string {
	marker := []byte("\x0c_device-info")
	idx := bytes.Index(buf, marker)
	if idx > 1 {
		// In DNS format: [length byte L] [L bytes of name] \x0c_device-info...
		for l := 1; l <= 63 && idx-1-l >= 0; l++ {
			if int(buf[idx-1-l]) == l {
				candidate := string(buf[idx-l : idx])
				candidate = strings.TrimSpace(candidate)
				if utf8.ValidString(candidate) && isCleanPrintableString(candidate) {
					return candidate
				}
			}
		}
	}
	return ""
}

func isCleanPrintableString(s string) bool {
	if len(s) == 0 {
		return false
	}
	for _, r := range s {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func isAppleModelSignature(rawModel string) bool {
	prefixes := []string{"Mac", "iPad", "iPhone", "AppleTV", "AudioAccessory", "Watch"}
	for _, p := range prefixes {
		if strings.HasPrefix(rawModel, p) {
			return true
		}
	}
	return false
}

// ResolveMDNSModel resolves verified raw model signature into a clean human-readable model description.
func ResolveMDNSModel(rawModel string) string {
	rawModel = strings.TrimSpace(rawModel)
	if rawModel == "" {
		return ""
	}
	if pretty, found := appleModelMap[rawModel]; found {
		return pretty
	}
	return fmt.Sprintf("Model: %s", rawModel)
}

// ResolveMacOSVersion maps Darwin kernel major release number in osxvers= to marketing macOS name
func ResolveMacOSVersion(osxvers string) string {
	osxvers = strings.TrimSpace(osxvers)
	if osxvers == "" {
		return ""
	}
	major := osxvers
	if dotIdx := strings.Index(osxvers, "."); dotIdx != -1 {
		major = osxvers[:dotIdx]
	}
	if ver, ok := darwinToMacOSMap[major]; ok {
		return ver
	}
	return fmt.Sprintf("macOS (Darwin %s)", osxvers)
}
