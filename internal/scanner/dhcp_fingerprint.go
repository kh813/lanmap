package scanner

import (
	"bytes"
	"fmt"
	"strings"
)

// DHCPFingerprintResult holds the inferred OS and metadata from DHCP fingerprints
type DHCPFingerprintResult struct {
	OS         string
	DeviceType string
	Confidence float64 // 0.0 to 1.0
	Evidence   string
}

type dhcpSig struct {
	exactParamList []byte
	subseqList     [][]byte
	vendorClassSub []string
	osName         string
	deviceType     string
	confidence     float64
}

// knownDHCPDatabase contains typical Option 55 Parameter Request List and Option 60 fingerprints
var knownDHCPDatabase = []dhcpSig{
	// --- Windows ---
	{
		exactParamList: []byte{1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252},
		osName:         "Windows 11 / 10",
		deviceType:     "PC",
		confidence:     0.95,
	},
	{
		exactParamList: []byte{1, 15, 3, 6, 44, 46, 47, 31, 33, 121, 249, 43, 252},
		osName:         "Windows 11 / 10",
		deviceType:     "PC",
		confidence:     0.95,
	},
	{
		exactParamList: []byte{1, 15, 3, 6, 44, 46, 47, 31, 33, 249, 43},
		osName:         "Windows 7 / 8 / Server",
		deviceType:     "PC",
		confidence:     0.90,
	},
	{
		subseqList: [][]byte{
			{1, 3, 6, 15, 31, 33, 43, 44, 46, 47},
			{1, 15, 3, 6, 44, 46, 47, 31, 33},
		},
		vendorClassSub: []string{"msft", "microsoft"},
		osName:         "Windows",
		deviceType:     "PC",
		confidence:     0.92,
	},

	// --- Apple macOS / iOS / iPadOS ---
	{
		exactParamList: []byte{1, 121, 3, 6, 15, 114, 119, 252},
		osName:         "iOS (Apple iPhone/iPad)",
		deviceType:     "Mobile",
		confidence:     0.95,
	},
	{
		exactParamList: []byte{1, 121, 3, 6, 15, 119, 252},
		osName:         "macOS / iOS (Apple)",
		deviceType:     "Apple Device",
		confidence:     0.90,
	},
	{
		exactParamList: []byte{1, 3, 6, 15, 119, 252},
		osName:         "macOS / iOS (Apple)",
		deviceType:     "Apple Device",
		confidence:     0.88,
	},
	{
		exactParamList: []byte{1, 3, 6, 15, 119},
		osName:         "tvOS (Apple TV)",
		deviceType:     "Media Player",
		confidence:     0.90,
	},

	// --- Android ---
	{
		exactParamList: []byte{1, 3, 6, 15, 26, 28, 51, 58, 59, 43},
		osName:         "Android OS",
		deviceType:     "Mobile",
		confidence:     0.95,
	},
	{
		exactParamList: []byte{1, 3, 6, 15, 26, 28, 33, 121},
		osName:         "Android OS",
		deviceType:     "Mobile",
		confidence:     0.90,
	},
	{
		subseqList: [][]byte{
			{1, 3, 6, 15, 26, 28},
		},
		vendorClassSub: []string{"android", "dhcpcd-"},
		osName:         "Android OS",
		deviceType:     "Mobile",
		confidence:     0.92,
	},

	// --- Linux Distributions ---
	{
		// systemd-networkd (Ubuntu Server, Debian, CoreOS, Arch)
		exactParamList: []byte{1, 3, 6, 12, 15, 26, 28, 42, 119, 121},
		osName:         "Linux (systemd-networkd)",
		deviceType:     "Server/Linux",
		confidence:     0.90,
	},
	{
		// dhcpcd (Raspberry Pi OS, Alpine, Void Linux)
		exactParamList: []byte{1, 3, 6, 12, 15, 26, 28, 33, 42, 43, 119, 121},
		osName:         "Raspberry Pi OS / Linux (dhcpcd)",
		deviceType:     "SBC/Linux",
		confidence:     0.92,
	},
	{
		// ISC dhclient (Ubuntu Desktop, Debian, RHEL)
		exactParamList: []byte{1, 28, 2, 3, 15, 6, 119, 12, 44, 47, 26, 121, 42},
		osName:         "Linux (ISC dhclient)",
		deviceType:     "Linux PC",
		confidence:     0.90,
	},
	{
		// Busybox udhcpc (OpenWrt, Alpine, Embedded Linux)
		exactParamList: []byte{1, 3, 6, 15, 33, 43},
		osName:         "Embedded Linux (udhcpc/OpenWrt)",
		deviceType:     "Router/IoT",
		confidence:     0.88,
	},

	// --- Game Consoles & IoT ---
	{
		exactParamList: []byte{1, 3, 6, 15, 28, 33, 43, 121},
		vendorClassSub: []string{"nintendo"},
		osName:         "Nintendo Switch OS",
		deviceType:     "Game Console",
		confidence:     0.98,
	},
	{
		subseqList: [][]byte{
			{1, 3, 6, 15, 12, 28, 43, 119},
		},
		vendorClassSub: []string{"playstation"},
		osName:         "PlayStation OS (Sony)",
		deviceType:     "Game Console",
		confidence:     0.98,
	},
	{
		subseqList: [][]byte{
			{1, 3, 6, 15, 28, 43},
		},
		vendorClassSub: []string{"esp32", "espressif", "tasmota", "esphome"},
		osName:         "FreeRTOS (ESP32/ESP8266)",
		deviceType:     "IoT Device",
		confidence:     0.95,
	},

	// --- Printers ---
	{
		exactParamList: []byte{1, 3, 6, 15, 43, 66, 67},
		osName:         "Printer Firmware (HP)",
		deviceType:     "Printer",
		confidence:     0.90,
	},
	{
		exactParamList: []byte{1, 3, 6, 15, 12, 28},
		vendorClassSub: []string{"canon"},
		osName:         "Canon Printer OS",
		deviceType:     "Printer",
		confidence:     0.92,
	},
	{
		exactParamList: []byte{1, 3, 6, 15, 44, 46, 47},
		vendorClassSub: []string{"brother"},
		osName:         "Brother Printer OS",
		deviceType:     "Printer",
		confidence:     0.92,
	},
}

// LookupDHCPFingerprint analyzes DHCP Option 55 and Option 60 to infer OS and confidence
func LookupDHCPFingerprint(paramList []byte, vendorClass, hostname string) *DHCPFingerprintResult {
	vcLower := strings.ToLower(strings.TrimSpace(vendorClass))
	hLower := strings.ToLower(strings.TrimSpace(hostname))

	// 1. Direct Vendor Class Matching (Option 60 is an explicit declaration)
	if vcLower != "" {
		if strings.Contains(vcLower, "msft 5.0") || strings.Contains(vcLower, "msft") {
			return &DHCPFingerprintResult{
				OS:         "Windows",
				DeviceType: "PC",
				Confidence: 0.95,
				Evidence:   fmt.Sprintf("DHCP Option 60 (%s)", vendorClass),
			}
		}
		if strings.Contains(vcLower, "android") {
			return &DHCPFingerprintResult{
				OS:         "Android OS",
				DeviceType: "Mobile",
				Confidence: 0.95,
				Evidence:   fmt.Sprintf("DHCP Option 60 (%s)", vendorClass),
			}
		}
		if strings.Contains(vcLower, "nintendo switch") {
			return &DHCPFingerprintResult{
				OS:         "Nintendo Switch OS",
				DeviceType: "Game Console",
				Confidence: 0.98,
				Evidence:   "DHCP Option 60 (Nintendo Switch)",
			}
		}
		if strings.Contains(vcLower, "playstation") {
			return &DHCPFingerprintResult{
				OS:         "PlayStation OS (Sony)",
				DeviceType: "Game Console",
				Confidence: 0.98,
				Evidence:   fmt.Sprintf("DHCP Option 60 (%s)", vendorClass),
			}
		}
		if strings.Contains(vcLower, "canon") || strings.Contains(vcLower, "epson") || strings.Contains(vcLower, "brother") || strings.Contains(vcLower, "ricoh") {
			return &DHCPFingerprintResult{
				OS:         "Printer Firmware",
				DeviceType: "Printer",
				Confidence: 0.92,
				Evidence:   fmt.Sprintf("DHCP Option 60 (%s)", vendorClass),
			}
		}
		if strings.Contains(vcLower, "cisco") {
			return &DHCPFingerprintResult{
				OS:         "Cisco Network OS",
				DeviceType: "Network",
				Confidence: 0.95,
				Evidence:   fmt.Sprintf("DHCP Option 60 (%s)", vendorClass),
			}
		}
	}

	// 2. Exact or Subsequence Option 55 Matching
	if len(paramList) > 0 {
		for _, sig := range knownDHCPDatabase {
			// Check exact match
			if len(sig.exactParamList) > 0 && bytes.Equal(paramList, sig.exactParamList) {
				// If vendorClass constraint exists, check it
				if len(sig.vendorClassSub) > 0 {
					matchedVC := false
					for _, v := range sig.vendorClassSub {
						if strings.Contains(vcLower, v) || strings.Contains(hLower, v) {
							matchedVC = true
							break
						}
					}
					if !matchedVC {
						continue
					}
				}

				return &DHCPFingerprintResult{
					OS:         sig.osName,
					DeviceType: sig.deviceType,
					Confidence: sig.confidence,
					Evidence:   fmt.Sprintf("DHCP Option 55 (Exact: %s)", formatParamList(paramList)),
				}
			}

			// Check subsequence match
			if len(sig.subseqList) > 0 {
				for _, sub := range sig.subseqList {
					if bytes.Contains(paramList, sub) {
						if len(sig.vendorClassSub) > 0 {
							matchedVC := false
							for _, v := range sig.vendorClassSub {
								if strings.Contains(vcLower, v) || strings.Contains(hLower, v) {
									matchedVC = true
									break
								}
							}
							if !matchedVC {
								continue
							}
						}

						return &DHCPFingerprintResult{
							OS:         sig.osName,
							DeviceType: sig.deviceType,
							Confidence: sig.confidence,
							Evidence:   fmt.Sprintf("DHCP Option 55 (Subsequence: %s)", formatParamList(sub)),
						}
					}
				}
			}
		}
	}

	// 3. Fallback generic heuristic from Option 55
	if len(paramList) > 0 {
		// Windows typical NetBIOS & DNS routing options: 44, 46, 47, 121, 249
		hasNetBIOS := bytes.IndexByte(paramList, 44) != -1 && bytes.IndexByte(paramList, 46) != -1
		hasStaticRoute := bytes.IndexByte(paramList, 121) != -1 || bytes.IndexByte(paramList, 249) != -1
		if hasNetBIOS && hasStaticRoute {
			return &DHCPFingerprintResult{
				OS:         "Windows",
				DeviceType: "PC",
				Confidence: 0.85,
				Evidence:   "DHCP Option 55 (Windows NetBIOS/Routes)",
			}
		}

		// Apple typical: 1, 3, 6, 15, 119, 252 (Domain Search + WPAD)
		hasDomainSearch := bytes.IndexByte(paramList, 119) != -1
		hasWPAD := bytes.IndexByte(paramList, 252) != -1
		if hasDomainSearch && hasWPAD && len(paramList) <= 8 {
			return &DHCPFingerprintResult{
				OS:         "macOS / iOS (Apple)",
				DeviceType: "Apple Device",
				Confidence: 0.82,
				Evidence:   "DHCP Option 55 (Apple typical options)",
			}
		}
	}

	return nil
}

func formatParamList(params []byte) string {
	if len(params) == 0 {
		return "[]"
	}
	var b strings.Builder
	for i, p := range params {
		if i > 0 {
			b.WriteString(",")
		}
		b.WriteString(fmt.Sprintf("%d", p))
		if i >= 6 {
			b.WriteString("...")
			break
		}
	}
	return b.String()
}
