package scanner

import (
	"fmt"
	"net"
	"strings"
	"time"
)

var appleModelMap = map[string]string{
	"MacBookPro18,1": "MacBook Pro (16-inch, 2021 M1 Pro)",
	"MacBookPro18,2": "MacBook Pro (16-inch, 2021 M1 Max)",
	"MacBookPro18,3": "MacBook Pro (14-inch, 2021 M1 Pro)",
	"MacBookPro18,4": "MacBook Pro (14-inch, 2021 M1 Max)",
	"MacBookPro17,1": "MacBook Pro (13-inch, M1, 2020)",
	"MacBookAir10,1": "MacBook Air (M1, 2020)",
	"Mac14,2":        "MacBook Air (M2, 2022)",
	"Mac14,7":        "MacBook Pro (13-inch, M2, 2022)",
	"Mac14,9":        "MacBook Pro (14-inch, M2 Pro, 2023)",
	"Mac14,10":       "MacBook Pro (16-inch, M2 Pro, 2023)",
	"Mac15,3":        "MacBook Pro (14-inch, M3, Nov 2023)",
	"Mac15,6":        "MacBook Pro (14-inch, M3 Pro, Nov 2023)",
	"Mac15,8":        "MacBook Pro (16-inch, M3 Pro, Nov 2023)",
	"Mac16,1":        "MacBook Pro (14-inch, M4, 2024)",
	"Mac16,5":        "MacBook Pro (16-inch, M4 Pro, 2024)",
	"Macmini9,1":     "Mac mini (M1, 2020)",
	"Mac14,3":        "Mac mini (M2, 2023)",
	"Mac14,12":       "Mac mini (M2 Pro, 2023)",
	"Mac16,10":       "Mac mini (M4, 2024)",
	"Mac16,15":       "Mac mini (M4 Pro, 2024)",
	"iPad14,3":       "iPad Pro 11-inch (4th Gen, M2)",
	"iPad14,4":       "iPad Pro 11-inch (4th Gen Wi-Fi+Cellular)",
	"iPad14,5":       "iPad Pro 12.9-inch (6th Gen, M2)",
	"iPad14,6":       "iPad Pro 12.9-inch (6th Gen Wi-Fi+Cellular)",
	"iPad16,3":       "iPad Pro 11-inch (M4, 2024)",
	"iPad16,4":       "iPad Pro 11-inch (M4, 2024 Wi-Fi+Cellular)",
	"iPad16,5":       "iPad Pro 13-inch (M4, 2024)",
	"iPad16,6":       "iPad Pro 13-inch (M4, 2024 Wi-Fi+Cellular)",
	"iPad13,1":       "iPad Air (4th Gen)",
	"iPad13,16":      "iPad Air (5th Gen, M1)",
	"iPad14,8":       "iPad Air 11-inch (M2, 2024)",
	"iPad14,10":      "iPad Air 13-inch (M2, 2024)",
	"iPhone15,2":     "iPhone 14 Pro",
	"iPhone15,3":     "iPhone 14 Pro Max",
	"iPhone16,1":     "iPhone 15 Pro",
	"iPhone16,2":     "iPhone 15 Pro Max",
	"iPhone17,1":     "iPhone 16 Pro",
	"iPhone17,2":     "iPhone 16 Pro Max",
	"AppleTV11,1":    "Apple TV 4K (2nd Gen)",
	"AppleTV14,1":    "Apple TV 4K (3rd Gen)",
	"AudioAccessory1,1": "HomePod",
	"AudioAccessory5,1": "HomePod mini",
}

// QueryMDNSDeviceInfo sends a unicast mDNS query to target IP:5353 to retrieve verified hardware model signature (e.g. MacBookPro18,4)
func QueryMDNSDeviceInfo(ipStr string, timeout time.Duration) string {
	addr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(ipStr, "5353"))
	if err != nil {
		return ""
	}
	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return ""
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
		return ""
	}

	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if err != nil || n < 12 {
		return ""
	}

	raw := string(buf[:n])
	// Look for model=MacBookPro18,4 or model=iPhone17,1
	if idx := strings.Index(raw, "model="); idx != -1 {
		part := raw[idx+6:]
		end := strings.IndexAny(part, "\x00\r\n\t ,;\"<>\x01\x02\x03\x04\x05\x06\x07\x08\x09")
		if end != -1 {
			part = part[:end]
		}
		part = strings.TrimSpace(part)
		if part != "" {
			return part
		}
	}
	return ""
}

// ResolveMDNSModel resolves verified raw model signature into a clean human-readable model description.
// It strictly maps evidence-based signatures (e.g. MacBookPro18,4) and does not guess from arbitrary hostnames.
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
