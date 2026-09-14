package scanner

import (
	"fmt"
	"strings"
	"time"
)

// OSScoreInput holds all passive & active signals observed from the target host
type OSScoreInput struct {
	IP              string
	Hostname        string
	Vendor          string // OUI vendor name
	TTL             int
	MDNSModel       string
	HTTPTitle       string
	UPnPName        string
	UPnPModel       string
	OpenPorts       string
	DHCPVendorClass string
	DHCPParamList   []byte
	InitialOS       string
}

// OSScoreResult holds the final deduced OS, confidence rating, and explanatory evidence
type OSScoreResult struct {
	OS         string  // e.g. "Windows 11 / 10", "macOS (Apple Silicon)", "Ubuntu 24.04 LTS"
	Confidence string  // "high", "medium", "low"
	Evidence   string  // e.g. "DHCP Option 55, TTL (128), SMB (Port 445)"
	Score      float64 // Numerical total weight for transparency
}

type osCandidate struct {
	category             string // e.g. "Windows", "macOS", "iOS", "Linux", "Android", "Network", "Printer", "IoT"
	refined              string // Detailed display name
	highestRefinedWeight float64
	score                float64
	reasons              []string
}

// ScoreOS computes the best matching OS using weighted multi-signal evidence
func ScoreOS(input OSScoreInput) OSScoreResult {
	candidates := make(map[string]*osCandidate)
	addScore := func(cat, refined string, weight float64, reason string) {
		if _, exists := candidates[cat]; !exists {
			candidates[cat] = &osCandidate{
				category: cat,
				refined:  refined,
				score:    0,
				reasons:  make([]string, 0),
			}
		}
		c := candidates[cat]
		c.score += weight
		if refined != "" && (c.refined == "" || weight > c.highestRefinedWeight) {
			c.refined = refined
			c.highestRefinedWeight = weight
		}
		c.reasons = append(c.reasons, reason)
	}

	evidenceLower := strings.ToLower(fmt.Sprintf("%s %s %s %s %s",
		input.MDNSModel, input.HTTPTitle, input.OpenPorts, input.UPnPName, input.UPnPModel))

	// 1. SSH Banner (Port 22) - Very High Confidence (0.95)
	if strings.Contains(input.OpenPorts, "22") && input.IP != "" {
		if banner := probeSSHBanner(input.IP, 80*time.Millisecond); banner != "" {
			if strings.Contains(banner, "Ubuntu-3ubuntu13") || strings.Contains(banner, "Ubuntu-1ubuntu") {
				addScore("Linux", "Ubuntu 24.04 LTS (Noble)", 0.95, fmt.Sprintf("SSH Banner (%s)", banner))
			} else if strings.Contains(banner, "Ubuntu-3ubuntu0") || strings.Contains(banner, "Ubuntu-1ubuntu0") {
				addScore("Linux", "Ubuntu 22.04 LTS (Jammy)", 0.95, fmt.Sprintf("SSH Banner (%s)", banner))
			} else if strings.Contains(banner, "Ubuntu") {
				addScore("Linux", "Ubuntu Linux", 0.90, fmt.Sprintf("SSH Banner (%s)", banner))
			} else if strings.Contains(banner, "Debian-5+deb12") {
				addScore("Linux", "Debian 12 (Bookworm)", 0.95, fmt.Sprintf("SSH Banner (%s)", banner))
			} else if strings.Contains(banner, "Debian") {
				addScore("Linux", "Debian Linux", 0.90, fmt.Sprintf("SSH Banner (%s)", banner))
			} else if strings.Contains(banner, "Raspbian") {
				addScore("Linux", "Raspberry Pi OS (Debian)", 0.95, fmt.Sprintf("SSH Banner (%s)", banner))
			} else if strings.Contains(banner, "dropbear") {
				addScore("Linux", "OpenWrt Linux (dropbear)", 0.95, fmt.Sprintf("SSH Banner (%s)", banner))
			} else {
				addScore("Linux", "Linux / OpenSSH", 0.80, fmt.Sprintf("SSH Banner (%s)", banner))
			}
		}
	}

	// 2. DHCP Option 55 / Option 60 Fingerprint (0.85 - 0.95)
	if dhcpRes := LookupDHCPFingerprint(input.DHCPParamList, input.DHCPVendorClass, input.Hostname); dhcpRes != nil {
		cat := "Linux"
		if strings.Contains(dhcpRes.OS, "Windows") {
			cat = "Windows"
		} else if strings.Contains(dhcpRes.OS, "macOS") {
			cat = "macOS"
		} else if strings.Contains(dhcpRes.OS, "iOS") {
			cat = "iOS"
		} else if strings.Contains(dhcpRes.OS, "Android") {
			cat = "Android"
		} else if strings.Contains(dhcpRes.OS, "Nintendo") || strings.Contains(dhcpRes.OS, "PlayStation") || strings.Contains(dhcpRes.OS, "FreeRTOS") {
			cat = "IoT"
		} else if strings.Contains(dhcpRes.OS, "Printer") {
			cat = "Printer"
		} else if strings.Contains(dhcpRes.OS, "Cisco") {
			cat = "Network"
		}
		addScore(cat, dhcpRes.OS, dhcpRes.Confidence, dhcpRes.Evidence)
	}

	// 3. mDNS Model Signatures (0.90 - 0.95)
	if input.MDNSModel != "" {
		m := input.MDNSModel
		if strings.Contains(m, "MacBook") || strings.Contains(m, "Mac mini") || strings.Contains(m, "Mac Studio") || strings.Contains(m, "iMac") {
			addScore("macOS", "macOS (Apple Silicon)", 0.95, fmt.Sprintf("mDNS Model (%s)", m))
		} else if strings.Contains(m, "iPhone") {
			addScore("iOS", "iOS (Apple iPhone)", 0.95, fmt.Sprintf("mDNS Model (%s)", m))
		} else if strings.Contains(m, "iPad") {
			addScore("iOS", "iPadOS (Apple iPad)", 0.95, fmt.Sprintf("mDNS Model (%s)", m))
		} else if strings.Contains(m, "Apple TV") {
			addScore("Apple", "tvOS (Apple TV)", 0.90, fmt.Sprintf("mDNS Model (%s)", m))
		} else if strings.Contains(m, "HomePod") {
			addScore("Apple", "HomePod OS", 0.90, fmt.Sprintf("mDNS Model (%s)", m))
		}
	}

	// 4. Web Titles & HTTP Headers (0.80 - 0.90)
	if strings.Contains(evidenceLower, "luci 24") || strings.Contains(evidenceLower, "openwrt 24") {
		addScore("Network", "OpenWrt 24.10 (Linux Router)", 0.90, "Web Title (OpenWrt 24)")
	} else if strings.Contains(evidenceLower, "luci 23") || strings.Contains(evidenceLower, "openwrt 23") {
		addScore("Network", "OpenWrt 23.05 (Linux Router)", 0.90, "Web Title (OpenWrt 23)")
	} else if strings.Contains(evidenceLower, "openwrt") || strings.Contains(evidenceLower, "luci") {
		addScore("Network", "OpenWrt (Linux Router)", 0.85, "Web Title (OpenWrt/LuCI)")
	} else if strings.Contains(evidenceLower, "synology") || strings.Contains(evidenceLower, "dsm") {
		addScore("Linux", "Synology DSM 7.x (Linux)", 0.88, "Web Title (Synology DSM)")
	} else if strings.Contains(evidenceLower, "proxmox") {
		addScore("Linux", "Proxmox VE (Debian Linux)", 0.90, "Web Title (Proxmox VE)")
	} else if strings.Contains(evidenceLower, "truenas") {
		addScore("Linux", "TrueNAS SCALE (Linux)", 0.88, "Web Title (TrueNAS)")
	}

	// 5. Network Equipment vendor / title (0.75 - 0.85)
	vLower := strings.ToLower(input.Vendor)
	if strings.Contains(vLower, "yamaha") || strings.Contains(evidenceLower, "yamaha") || strings.Contains(evidenceLower, "rtx") {
		addScore("Network", "Yamaha Network OS (RevBoot)", 0.85, "Vendor/UPnP (Yamaha)")
	} else if strings.Contains(vLower, "cisco") || strings.Contains(evidenceLower, "cisco") {
		addScore("Network", "Cisco IOS / Network OS", 0.85, "Vendor/UPnP (Cisco)")
	} else if strings.Contains(vLower, "netgear") || strings.Contains(evidenceLower, "netgear") {
		addScore("Network", "Netgear Firmware (Embedded Linux)", 0.80, "Vendor/UPnP (Netgear)")
	} else if strings.Contains(vLower, "ubiquiti") || strings.Contains(evidenceLower, "ubnt") || strings.Contains(evidenceLower, "unifi") {
		addScore("Network", "UniFi OS (Embedded Linux)", 0.85, "Vendor/UPnP (UniFi)")
	}

	// 6. SMB & Windows ports (0.60 - 0.80)
	if strings.Contains(input.OpenPorts, "445") || strings.Contains(input.OpenPorts, "139") {
		if strings.Contains(evidenceLower, "server") {
			addScore("Windows", "Windows Server", 0.80, "Port 445/139 (SMB) & Server")
		} else {
			addScore("Windows", "Windows 11 / 10", 0.65, "Port 445/139 (SMB)")
		}
	}

	// 7. OUI Vendor (0.35 - 0.60)
	if strings.Contains(vLower, "apple") {
		addScore("Apple", "macOS / iOS (Apple)", 0.40, "OUI Vendor (Apple)")
	} else if strings.Contains(vLower, "microsoft") {
		addScore("Windows", "Windows", 0.40, "OUI Vendor (Microsoft)")
	} else if strings.Contains(vLower, "espressif") {
		addScore("IoT", "FreeRTOS (ESP32/ESP8266)", 0.70, "OUI Vendor (Espressif)")
	} else if strings.Contains(vLower, "canon") || strings.Contains(vLower, "epson") || strings.Contains(vLower, "brother") || strings.Contains(vLower, "fuji xerox") || strings.Contains(vLower, "ricoh") {
		addScore("Printer", "Printer Firmware", 0.65, fmt.Sprintf("OUI Vendor (%s)", input.Vendor))
	} else if strings.Contains(vLower, "nintendo") {
		addScore("IoT", "Nintendo Switch OS", 0.85, "OUI Vendor (Nintendo)")
	} else if strings.Contains(vLower, "sony") && (strings.Contains(evidenceLower, "playstation") || strings.Contains(evidenceLower, "ps5")) {
		addScore("IoT", "PlayStation OS (Sony)", 0.85, "OUI Vendor/Name (Sony)")
	}

	// 8. Ping TTL (0.25 - 0.35)
	if input.TTL > 0 {
		if input.TTL > 64 && input.TTL <= 128 {
			addScore("Windows", "Windows", 0.30, fmt.Sprintf("TTL (%d)", input.TTL))
		} else if input.TTL <= 64 {
			addScore("Unix/Linux", "Linux / Unix", 0.25, fmt.Sprintf("TTL (%d)", input.TTL))
		} else if input.TTL > 128 {
			addScore("Network", "Network Device / OS", 0.35, fmt.Sprintf("TTL (%d)", input.TTL))
		}
	}

	// 9. Initial OS Fallback
	if input.InitialOS != "" && input.InitialOS != "Unknown" && input.InitialOS != "Linux / Unix" {
		addScore("Initial", input.InitialOS, 0.20, fmt.Sprintf("Initial OS (%s)", input.InitialOS))
	}

	// Resolve winner candidate with highest score
	var bestCandidate *osCandidate
	for _, c := range candidates {
		if bestCandidate == nil || c.score > bestCandidate.score {
			bestCandidate = c
		}
	}

	if bestCandidate == nil || bestCandidate.score < 0.1 {
		fallbackOS := "Linux / Unix"
		if input.InitialOS != "" && input.InitialOS != "Unknown" {
			fallbackOS = input.InitialOS
		}
		return OSScoreResult{
			OS:         fallbackOS,
			Confidence: "low",
			Evidence:   "Default heuristic fallback",
			Score:      0.1,
		}
	}

	// Confidence classification
	confidence := "low"
	if bestCandidate.score >= 1.2 || hasDecisiveEvidence(bestCandidate.reasons) {
		confidence = "high"
	} else if bestCandidate.score >= 0.6 {
		confidence = "medium"
	}

	evidenceStr := strings.Join(bestCandidate.reasons, ", ")
	osName := bestCandidate.refined
	if osName == "" {
		osName = bestCandidate.category
	}

	return OSScoreResult{
		OS:         osName,
		Confidence: confidence,
		Evidence:   evidenceStr,
		Score:      bestCandidate.score,
	}
}

func hasDecisiveEvidence(reasons []string) bool {
	for _, r := range reasons {
		if strings.Contains(r, "SSH Banner") ||
			strings.Contains(r, "Exact:") ||
			strings.Contains(r, "mDNS Model") ||
			strings.Contains(r, "Option 60") {
			return true
		}
	}
	return false
}
