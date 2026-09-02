package scanner

import (
	"fmt"
	"strings"
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

// ResolveMDNSModel resolves raw model string or hostname into a clean model description
func ResolveMDNSModel(rawModel string, hostname string) string {
	rawModel = strings.TrimSpace(rawModel)
	if pretty, found := appleModelMap[rawModel]; found {
		return pretty
	}

	lowerHost := strings.ToLower(hostname)
	if strings.Contains(lowerHost, "ipad") {
		if strings.Contains(lowerHost, "m4") {
			return "Apple iPad Pro (M4 1TB)"
		}
		return "Apple iPad"
	}
	if strings.Contains(lowerHost, "iphone16p") || (strings.Contains(lowerHost, "iphone16") && strings.Contains(lowerHost, "pro")) {
		return "Apple iPhone 16 Pro"
	}
	if strings.Contains(lowerHost, "iphone") {
		return "Apple iPhone"
	}
	if strings.Contains(lowerHost, "watch") {
		return "Apple Watch"
	}
	if strings.Contains(lowerHost, "mbpm1m") || strings.Contains(lowerHost, "mbp-m1") {
		return "Apple MacBook Pro (16-inch, M1 Pro)"
	}
	if strings.Contains(lowerHost, "mac.parkside") {
		return "Apple Mac"
	}
	if strings.Contains(lowerHost, "fold5") {
		return "Samsung Galaxy Z Fold5 5G"
	}
	if strings.Contains(lowerHost, "google-home") {
		return "Google Home Mini"
	}
	if strings.Contains(lowerHost, "espressif") {
		return "Espressif IoT Device (ESP32/ESP8266)"
	}
	if strings.Contains(lowerHost, "openwrt") {
		return "OpenWrt Network Router"
	}

	if rawModel != "" {
		return fmt.Sprintf("Model: %s", rawModel)
	}
	return ""
}
