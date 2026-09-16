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
	MDNSDevice      string
	MacOSVer        string
	NetBIOSName     string
	NetBIOSUser     string
	NetBIOSDomain   string
	IsNetBIOS       bool
	HTTPTitle       string
	UPnPName        string
	UPnPModel       string
	OpenPorts       string
	DHCPVendorClass string
	DHCPParamList   []byte
	SMBOSVersion    string
	WSDManufacturer string
	WSDModel        string
	SNMPDescr       string
	InitialOS       string
}

// OSScoreResult holds the final deduced OS, confidence rating, and explanatory evidence
type OSScoreResult struct {
	OS         string  // e.g. "Windows 11 / 10", "macOS 15 Sequoia", "Ubuntu 24.04 LTS"
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

	evidenceLower := strings.ToLower(fmt.Sprintf("%s %s %s %s %s %s",
		input.MDNSModel, input.MDNSDevice, input.HTTPTitle, input.OpenPorts, input.UPnPName, input.UPnPModel))

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
				vLower := strings.ToLower(input.Vendor)
				if strings.Contains(vLower, "mist") || strings.Contains(vLower, "juniper") {
					addScore("Network", "Mist AI (Mist Systems / Juniper)", 0.96, fmt.Sprintf("SSH Banner (Dropbear) & Vendor (%s)", input.Vendor))
				} else if strings.Contains(vLower, "aruba") || strings.Contains(vLower, "hewlett") {
					addScore("Network", "ArubaOS (Aruba Networks / HPE)", 0.96, fmt.Sprintf("SSH Banner (Dropbear) & Vendor (%s)", input.Vendor))
				} else if strings.Contains(vLower, "fortinet") || strings.Contains(vLower, "fortigate") {
					addScore("Network", "FortiOS (Fortinet)", 0.96, fmt.Sprintf("SSH Banner (Dropbear) & Vendor (%s)", input.Vendor))
				} else if strings.Contains(vLower, "yamaha") {
					addScore("Network", "Yamaha Network OS (RevBoot)", 0.96, fmt.Sprintf("SSH Banner (Dropbear) & Vendor (%s)", input.Vendor))
				} else if strings.Contains(vLower, "ubiquiti") {
					addScore("Network", "UniFi OS (Embedded Linux)", 0.96, fmt.Sprintf("SSH Banner (Dropbear) & Vendor (%s)", input.Vendor))
				} else if strings.Contains(vLower, "netgear") {
					addScore("Network", "Netgear Firmware (Embedded Linux)", 0.95, fmt.Sprintf("SSH Banner (Dropbear) & Vendor (%s)", input.Vendor))
				} else {
					addScore("Linux", "OpenWrt Linux (dropbear)", 0.90, fmt.Sprintf("SSH Banner (%s)", banner))
				}
			} else {
				vLower := strings.ToLower(input.Vendor)
				if strings.Contains(vLower, "mist") || strings.Contains(vLower, "juniper") {
					addScore("Network", "Mist AI (Mist Systems / Juniper)", 0.95, fmt.Sprintf("SSH Banner (%s) & Vendor (%s)", banner, input.Vendor))
				} else if strings.Contains(vLower, "aruba") || strings.Contains(vLower, "hewlett") {
					addScore("Network", "ArubaOS (Aruba Networks / HPE)", 0.95, fmt.Sprintf("SSH Banner (%s) & Vendor (%s)", banner, input.Vendor))
				} else if strings.Contains(vLower, "fortinet") || strings.Contains(vLower, "fortigate") {
					addScore("Network", "FortiOS (Fortinet)", 0.95, fmt.Sprintf("SSH Banner (%s) & Vendor (%s)", banner, input.Vendor))
				} else if strings.Contains(vLower, "cisco") {
					addScore("Network", "Cisco IOS / Network OS", 0.95, fmt.Sprintf("SSH Banner (%s) & Vendor (%s)", banner, input.Vendor))
				} else {
					addScore("Linux", "Linux / OpenSSH", 0.80, fmt.Sprintf("SSH Banner (%s)", banner))
				}
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

	// 3. mDNS Model Signatures & macOS Version (0.90 - 0.98)
	if input.MacOSVer != "" {
		addScore("macOS", input.MacOSVer, 0.98, fmt.Sprintf("mDNS osxvers (%s)", input.MacOSVer))
	} else if input.MDNSModel != "" {
		m := input.MDNSModel
		if strings.Contains(m, "MacBook") || strings.Contains(m, "Mac mini") || strings.Contains(m, "Mac Studio") || strings.Contains(m, "iMac") || strings.Contains(m, "Mac Pro") {
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

	// 3.5 SMB NTLMSSP OS Version Signature (0.98)
	if input.SMBOSVersion != "" {
		addScore("Windows", input.SMBOSVersion, 0.98, fmt.Sprintf("SMB NTLMSSP (%s)", input.SMBOSVersion))
	}

	// 3.6 WS-Discovery (WSD) Model / Manufacturer Signature (0.92)
	if input.WSDModel != "" || input.WSDManufacturer != "" {
		combinedWSD := strings.ToLower(input.WSDManufacturer + " " + input.WSDModel)
		if strings.Contains(combinedWSD, "canon") || strings.Contains(combinedWSD, "epson") || strings.Contains(combinedWSD, "brother") || strings.Contains(combinedWSD, "fuji") || strings.Contains(combinedWSD, "ricoh") || strings.Contains(combinedWSD, "kyocera") || strings.Contains(combinedWSD, "hp") && strings.Contains(combinedWSD, "laserjet") {
			addScore("Printer", "Printer Firmware (WSD)", 0.92, fmt.Sprintf("WSD Device (%s)", input.WSDModel))
		} else {
			addScore("Windows", "Windows 11 / 10", 0.90, fmt.Sprintf("WSD PC (%s %s)", input.WSDManufacturer, input.WSDModel))
		}
	}

	// 3.7 SNMP sysDescr Signature (0.95)
	if input.SNMPDescr != "" {
		sLower := strings.ToLower(input.SNMPDescr)
		if strings.Contains(sLower, "synology") || strings.Contains(sLower, "dsm") {
			addScore("Linux", "Synology DSM (Linux)", 0.96, fmt.Sprintf("SNMP sysDescr (%s)", input.SNMPDescr))
		} else if strings.Contains(sLower, "qnap") || strings.Contains(sLower, "qts") {
			addScore("Linux", "QNAP QTS (Linux)", 0.96, fmt.Sprintf("SNMP sysDescr (%s)", input.SNMPDescr))
		} else if strings.Contains(sLower, "cisco") {
			addScore("Network", "Cisco IOS", 0.95, fmt.Sprintf("SNMP sysDescr (%s)", input.SNMPDescr))
		} else if strings.Contains(sLower, "yamaha") {
			addScore("Network", "Yamaha Network OS", 0.95, fmt.Sprintf("SNMP sysDescr (%s)", input.SNMPDescr))
		} else if strings.Contains(sLower, "linux") {
			addScore("Linux", "Linux Kernel (SNMP)", 0.92, fmt.Sprintf("SNMP sysDescr (%s)", input.SNMPDescr))
		} else if strings.Contains(sLower, "windows") {
			addScore("Windows", "Windows (SNMP)", 0.92, fmt.Sprintf("SNMP sysDescr (%s)", input.SNMPDescr))
		}
	}

	// Check if device is a printer/MFP
	isPrinterCandidate := func() bool {
		vL := strings.ToLower(input.Vendor)
		hL := strings.ToLower(input.Hostname)
		nbL := strings.ToLower(input.NetBIOSName)
		eL := evidenceLower
		pPorts := input.OpenPorts

		// Distinct printer ports
		if strings.Contains(pPorts, "9100") || strings.Contains(pPorts, "631") || strings.Contains(pPorts, "515") {
			return true
		}
		// Distinct printer vendors
		if strings.Contains(vL, "canon") || strings.Contains(vL, "epson") || strings.Contains(vL, "brother") ||
			strings.Contains(vL, "ricoh") || strings.Contains(vL, "fuji xerox") || strings.Contains(vL, "fujifilm") ||
			strings.Contains(vL, "kyocera") || strings.Contains(vL, "konica") || strings.Contains(vL, "minolta") ||
			strings.Contains(vL, "toshiba tec") || strings.Contains(vL, "riso") || strings.Contains(vL, "oki data") ||
			strings.Contains(vL, "lexmark") || strings.Contains(vL, "zebra") || strings.Contains(vL, "sato") ||
			strings.Contains(vL, "hp print") || strings.Contains(vL, "hewlett-packard print") {
			return true
		}
		// Distinct hostnames / NetBIOS names / Web evidence
		if strings.Contains(hL, "printer") || strings.Contains(hL, "laserjet") || strings.Contains(hL, "deskjet") || strings.Contains(hL, "taskalfa") || strings.Contains(hL, "bizhub") || strings.Contains(hL, "imagerunner") || strings.Contains(hL, "docuprint") || strings.Contains(hL, "apeos") || strings.Contains(hL, "imagio") ||
			strings.Contains(nbL, "printer") || strings.Contains(nbL, "laserjet") || strings.Contains(nbL, "taskalfa") || strings.Contains(nbL, "bizhub") || strings.Contains(nbL, "mfp") ||
			strings.Contains(eL, "printer") || strings.Contains(eL, "laserjet") || strings.Contains(eL, "web image monitor") || strings.Contains(eL, "centreware") || strings.Contains(eL, "command center") {
			return true
		}
		return false
	}()

	// 3.5 NetBIOS Node Signatures (0.85 - 0.95)
	if input.IsNetBIOS {
		nbLower := strings.ToLower(input.NetBIOSName)
		if isPrinterCandidate {
			addScore("Printer", "Printer Firmware (Embedded Linux/BSD with Samba)", 0.92, fmt.Sprintf("NetBIOS Node (%s, Samba MFP)", input.NetBIOSName))
		} else if strings.Contains(nbLower, "server") || strings.Contains(nbLower, "dc") || strings.Contains(nbLower, "ad") {
			addScore("Windows", "Windows Server", 0.95, fmt.Sprintf("NetBIOS Node (%s, Domain: %s)", input.NetBIOSName, input.NetBIOSDomain))
		} else {
			addScore("Windows", "Windows 11 / 10", 0.92, fmt.Sprintf("NetBIOS Node (%s, Domain: %s)", input.NetBIOSName, input.NetBIOSDomain))
		}
	}

	webEvidenceLower := strings.ToLower(fmt.Sprintf("%s %s %s", input.HTTPTitle, input.UPnPName, input.UPnPModel))

	// 4. Web Titles & HTTP Headers (0.80 - 0.90)
	if strings.Contains(webEvidenceLower, "web image monitor") || strings.Contains(webEvidenceLower, "ricoh") {
		addScore("Printer", "Ricoh Printer/MFP OS (Embedded Linux/BSD)", 0.92, "Web/Title (Ricoh Web Image Monitor)")
	} else if strings.Contains(webEvidenceLower, "centreware") || strings.Contains(webEvidenceLower, "fujifilm") || strings.Contains(webEvidenceLower, "fuji xerox") || strings.Contains(webEvidenceLower, "apeos") {
		addScore("Printer", "Fujifilm MFP Firmware (Embedded Linux/BSD)", 0.92, "Web/Title (Fujifilm/FujiXerox)")
	} else if strings.Contains(webEvidenceLower, "command center") || strings.Contains(webEvidenceLower, "taskalfa") || strings.Contains(webEvidenceLower, "kyocera") {
		addScore("Printer", "Kyocera MFP Firmware (Embedded Linux/BSD)", 0.92, "Web/Title (Kyocera Command Center)")
	} else if strings.Contains(webEvidenceLower, "pagescope") || strings.Contains(webEvidenceLower, "bizhub") || strings.Contains(webEvidenceLower, "konica") {
		addScore("Printer", "Konica Minolta MFP Firmware (Embedded Linux/BSD)", 0.92, "Web/Title (Konica Minolta PageScope)")
	} else if strings.Contains(webEvidenceLower, "remote ui") || strings.Contains(webEvidenceLower, "imagerunner") || strings.Contains(webEvidenceLower, "canon") {
		addScore("Printer", "Canon MFP Firmware (Embedded Linux)", 0.92, "Web/Title (Canon Remote UI)")
	} else if strings.Contains(webEvidenceLower, "fortigate") || strings.Contains(webEvidenceLower, "fortinet") || strings.Contains(webEvidenceLower, "fortios") {
		addScore("Network", "FortiOS (Fortinet)", 0.92, "Web/Title (FortiGate)")
	} else if strings.Contains(webEvidenceLower, "aruba") || strings.Contains(webEvidenceLower, "instant on") {
		addScore("Network", "ArubaOS (Aruba Networks / HPE)", 0.90, "Web/Title (Aruba)")
	} else if strings.Contains(webEvidenceLower, "mist") || strings.Contains(webEvidenceLower, "juniper") {
		addScore("Network", "Mist AI / Junos OS (Mist Systems)", 0.90, "Web/Title (Mist/Juniper)")
	} else if strings.Contains(webEvidenceLower, "luci 24") || strings.Contains(webEvidenceLower, "openwrt 24") {
		addScore("Network", "OpenWrt 24.10 (Linux Router)", 0.90, "Web Title (OpenWrt 24)")
	} else if strings.Contains(webEvidenceLower, "luci 23") || strings.Contains(webEvidenceLower, "openwrt 23") {
		addScore("Network", "OpenWrt 23.05 (Linux Router)", 0.90, "Web Title (OpenWrt 23)")
	} else if strings.Contains(webEvidenceLower, "openwrt") || strings.Contains(webEvidenceLower, "luci") {
		addScore("Network", "OpenWrt (Linux Router)", 0.85, "Web Title (OpenWrt/LuCI)")
	} else if strings.Contains(webEvidenceLower, "synology") || strings.Contains(webEvidenceLower, "diskstation") || strings.Contains(webEvidenceLower, "rackstation") || strings.Contains(webEvidenceLower, "synology dsm") {
		addScore("Linux", "Synology DSM (Linux)", 0.90, "Web Title (Synology DSM)")
	} else if strings.Contains(webEvidenceLower, "qnap") || strings.Contains(webEvidenceLower, "qts") {
		addScore("Linux", "QNAP QTS (Linux)", 0.90, "Web Title (QNAP QTS)")
	} else if strings.Contains(webEvidenceLower, "asustor") || strings.Contains(webEvidenceLower, "adm") {
		addScore("Linux", "ASUSTOR ADM (Linux)", 0.90, "Web Title (ASUSTOR)")
	} else if strings.Contains(webEvidenceLower, "proxmox") {
		addScore("Linux", "Proxmox VE (Debian Linux)", 0.90, "Web Title (Proxmox VE)")
	} else if strings.Contains(webEvidenceLower, "truenas") || strings.Contains(webEvidenceLower, "freenas") {
		addScore("Linux", "TrueNAS SCALE (Linux)", 0.88, "Web Title (TrueNAS)")
	} else if strings.Contains(webEvidenceLower, "hikvision") || strings.Contains(webEvidenceLower, "web components") {
		addScore("Camera", "Hikvision Embedded Linux", 0.90, "Web Title (Hikvision)")
	} else if strings.Contains(webEvidenceLower, "dahua") {
		addScore("Camera", "Dahua Embedded Linux", 0.90, "Web Title (Dahua)")
	} else if strings.Contains(webEvidenceLower, "axis") {
		addScore("Camera", "AXIS OS (Linux)", 0.90, "Web Title (AXIS)")
	} else if strings.Contains(webEvidenceLower, "yealink") {
		addScore("VoIP", "Yealink VoIP OS", 0.90, "Web Title (Yealink)")
	} else if strings.Contains(webEvidenceLower, "polycom") || strings.Contains(webEvidenceLower, "soundpoint") {
		addScore("VoIP", "Poly UC Software (VoIP)", 0.90, "Web Title (Polycom)")
	} else if strings.Contains(webEvidenceLower, "grandstream") {
		addScore("VoIP", "Grandstream VoIP OS", 0.90, "Web Title (Grandstream)")
	}

	// 5. Network Equipment vendor / title (0.75 - 0.88)
	vLower := strings.ToLower(input.Vendor)
	if strings.Contains(vLower, "fortinet") || strings.Contains(vLower, "fortigate") {
		addScore("Network", "FortiOS (Fortinet)", 0.88, "Vendor (Fortinet)")
	} else if strings.Contains(vLower, "aruba") {
		addScore("Network", "ArubaOS (Aruba Networks / HPE)", 0.88, "Vendor (Aruba)")
	} else if strings.Contains(vLower, "mist") {
		addScore("Network", "Mist AI (Mist Systems / Juniper)", 0.88, "Vendor (Mist Systems)")
	} else if strings.Contains(vLower, "juniper") {
		addScore("Network", "Junos OS (Juniper Networks)", 0.85, "Vendor (Juniper)")
	} else if strings.Contains(vLower, "yamaha") || strings.Contains(evidenceLower, "yamaha") || strings.Contains(evidenceLower, "rtx") || strings.Contains(evidenceLower, "wlx") {
		addScore("Network", "Yamaha Network OS (RevBoot)", 0.88, "Vendor/UPnP (Yamaha)")
	} else if strings.Contains(vLower, "allied telesis") || strings.Contains(vLower, "allied") || strings.Contains(evidenceLower, "centrecom") {
		addScore("Network", "AlliedWare Plus (Allied Telesis)", 0.85, "Vendor (Allied Telesis)")
	} else if strings.Contains(vLower, "cisco") || strings.Contains(evidenceLower, "cisco") {
		if strings.Contains(vLower, "cisco ip phone") || strings.Contains(evidenceLower, "cisco ip phone") {
			addScore("VoIP", "Cisco IP Phone Firmware (SIP)", 0.90, "Vendor (Cisco VoIP)")
		} else {
			addScore("Network", "Cisco IOS / Network OS", 0.85, "Vendor/UPnP (Cisco)")
		}
	} else if strings.Contains(vLower, "netgear") || strings.Contains(evidenceLower, "netgear") || strings.Contains(evidenceLower, "orbi") || strings.Contains(evidenceLower, "nighthawk") {
		addScore("Network", "Netgear Firmware (Embedded Linux)", 0.82, "Vendor/UPnP (Netgear)")
	} else if strings.Contains(vLower, "ubiquiti") || strings.Contains(evidenceLower, "ubnt") || strings.Contains(evidenceLower, "unifi") {
		addScore("Network", "UniFi OS (Embedded Linux)", 0.88, "Vendor/UPnP (UniFi)")
	} else if strings.Contains(vLower, "nec") || strings.Contains(evidenceLower, "aterm") {
		addScore("Network", "NEC Aterm / Network Firmware", 0.80, "Vendor (NEC)")
	} else if strings.Contains(vLower, "buffalo") || strings.Contains(evidenceLower, "airstation") {
		if strings.Contains(evidenceLower, "terastation") || strings.Contains(evidenceLower, "linkstation") {
			addScore("Linux", "Buffalo NAS Firmware (Linux)", 0.85, "Vendor/UPnP (Buffalo NAS)")
		} else {
			addScore("Network", "Buffalo AirStation Firmware", 0.80, "Vendor/UPnP (Buffalo)")
		}
	} else if strings.Contains(vLower, "tp-link") || strings.Contains(evidenceLower, "omada") || strings.Contains(evidenceLower, "deco") {
		addScore("Network", "TP-Link Firmware (Embedded Linux)", 0.80, "Vendor/UPnP (TP-Link)")
	}

	// 5.5 Surveillance Cameras & VoIP Phones (0.75 - 0.88)
	if strings.Contains(vLower, "hikvision") {
		addScore("Camera", "Hikvision Embedded Linux", 0.88, "Vendor (Hikvision)")
	} else if strings.Contains(vLower, "dahua") {
		addScore("Camera", "Dahua Embedded Linux", 0.88, "Vendor (Dahua)")
	} else if strings.Contains(vLower, "axis") {
		addScore("Camera", "AXIS OS (Embedded Linux)", 0.88, "Vendor (Axis Communications)")
	} else if strings.Contains(vLower, "hanwha") || strings.Contains(vLower, "techwin") {
		addScore("Camera", "Hanwha Wisenet OS", 0.88, "Vendor (Hanwha)")
	} else if strings.Contains(vLower, "yealink") {
		addScore("VoIP", "Yealink VoIP OS", 0.88, "Vendor (Yealink)")
	} else if strings.Contains(vLower, "poly") || strings.Contains(vLower, "polycom") {
		addScore("VoIP", "Poly UC Software (VoIP)", 0.88, "Vendor (Polycom)")
	} else if strings.Contains(vLower, "grandstream") {
		addScore("VoIP", "Grandstream VoIP OS", 0.88, "Vendor (Grandstream)")
	} else if strings.Contains(vLower, "snom") {
		addScore("VoIP", "Snom VoIP OS", 0.88, "Vendor (Snom)")
	} else if strings.Contains(vLower, "fanvil") {
		addScore("VoIP", "Fanvil VoIP OS", 0.88, "Vendor (Fanvil)")
	} else if strings.Contains(input.OpenPorts, "554") && (strings.Contains(input.OpenPorts, "8000") || strings.Contains(input.OpenPorts, "8899") || strings.Contains(input.OpenPorts, "37777")) {
		addScore("Camera", "IP Camera / ONVIF Device", 0.80, "Ports 554/8000/8899 (RTSP/ONVIF)")
	} else if strings.Contains(input.OpenPorts, "5060") || strings.Contains(input.OpenPorts, "5061") {
		addScore("VoIP", "VoIP / SIP Terminal", 0.78, "Port 5060/5061 (SIP)")
	}

	// 5.6 IoT, Smart Home & Microcontrollers (0.70 - 0.85)
	if strings.Contains(vLower, "switchbot") || strings.Contains(vLower, "woan") {
		addScore("IoT", "SwitchBot OS (IoT)", 0.88, "Vendor (SwitchBot)")
	} else if strings.Contains(vLower, "espressif") {
		addScore("IoT", "FreeRTOS (ESP32/ESP8266)", 0.80, "OUI Vendor (Espressif)")
	} else if strings.Contains(vLower, "tuya") {
		addScore("IoT", "Tuya Smart OS (IoT)", 0.85, "Vendor (Tuya)")
	} else if strings.Contains(vLower, "shelly") {
		addScore("IoT", "Shelly Firmware (Mongoose OS)", 0.85, "Vendor (Shelly)")
	} else if strings.Contains(vLower, "philips hue") || strings.Contains(vLower, "philips lighting") {
		addScore("IoT", "Philips Hue Bridge OS", 0.88, "Vendor (Philips Hue)")
	} else if strings.Contains(vLower, "xiaomi") || strings.Contains(vLower, "aqara") {
		addScore("IoT", "Xiaomi / Aqara Smart OS", 0.82, "Vendor (Xiaomi)")
	} else if strings.Contains(input.OpenPorts, "1883") || strings.Contains(input.OpenPorts, "8883") {
		addScore("IoT", "Embedded IoT (MQTT)", 0.75, "Port 1883 (MQTT)")
	}

	// 6. SMB & Windows ports (0.60 - 0.80)
	if strings.Contains(input.OpenPorts, "445") || strings.Contains(input.OpenPorts, "139") {
		if isPrinterCandidate {
			addScore("Printer", "Printer Firmware (Embedded Linux/BSD with Samba)", 0.88, "Port 445/139 (Samba MFP)")
		} else if strings.Contains(evidenceLower, "server") {
			addScore("Windows", "Windows Server", 0.80, "Port 445/139 (SMB) & Server")
		} else {
			addScore("Windows", "Windows 11 / 10", 0.65, "Port 445/139 (SMB)")
		}
	}

	// 6.5 Dedicated Printer Ports (Port 9100 RAW, 631 IPP, 515 LPD)
	if strings.Contains(input.OpenPorts, "9100") || strings.Contains(input.OpenPorts, "631") || strings.Contains(input.OpenPorts, "515") {
		addScore("Printer", "Printer Firmware (Embedded Linux/BSD)", 0.90, "Port 9100/631/515 (RAW/IPP/LPD Printer)")
	}

	// 7. OUI Vendor & Hostname patterns (0.35 - 0.75)
	hLower := strings.ToLower(input.Hostname)
	if strings.Contains(vLower, "apple") {
		addScore("Apple", "macOS / iOS (Apple)", 0.40, "OUI Vendor (Apple)")
	} else if strings.Contains(vLower, "microsoft") {
		addScore("Windows", "Windows", 0.40, "OUI Vendor (Microsoft)")
	} else if strings.Contains(vLower, "raspberry") || strings.Contains(hLower, "raspberrypi") {
		addScore("Linux", "Raspberry Pi OS (Linux)", 0.75, "Vendor/Hostname (Raspberry Pi)")
	} else if strings.Contains(vLower, "canon") || strings.Contains(vLower, "epson") || strings.Contains(vLower, "brother") ||
		strings.Contains(vLower, "fuji xerox") || strings.Contains(vLower, "fujifilm") || strings.Contains(vLower, "ricoh") ||
		strings.Contains(vLower, "kyocera") || strings.Contains(vLower, "konica") || strings.Contains(vLower, "minolta") ||
		strings.Contains(vLower, "toshiba tec") || strings.Contains(vLower, "riso") || strings.Contains(vLower, "oki data") ||
		strings.Contains(vLower, "lexmark") || strings.Contains(vLower, "zebra") || strings.Contains(vLower, "sato") {
		addScore("Printer", "Printer Firmware (Embedded Linux/BSD)", 0.88, fmt.Sprintf("OUI Vendor (%s)", input.Vendor))
	} else if strings.Contains(vLower, "nintendo") {
		addScore("IoT", "Nintendo Switch OS", 0.85, "OUI Vendor (Nintendo)")
	} else if strings.Contains(vLower, "sony") && (strings.Contains(evidenceLower, "playstation") || strings.Contains(evidenceLower, "ps5")) {
		addScore("IoT", "PlayStation OS (Sony)", 0.85, "OUI Vendor/Name (Sony)")
	}

	// 8. Ping TTL (0.40 - 0.50)
	if input.TTL > 0 {
		if input.TTL > 64 && input.TTL <= 128 {
			addScore("Windows", "Windows", 0.50, fmt.Sprintf("TTL (%d: Windows standard)", input.TTL))
		} else if input.TTL <= 64 {
			addScore("Unix/Linux", "Linux / Unix", 0.40, fmt.Sprintf("TTL (%d: Unix/Linux standard)", input.TTL))
		} else if input.TTL > 128 {
			addScore("Network", "Network Device / OS", 0.45, fmt.Sprintf("TTL (%d: Network standard)", input.TTL))
		}
	}

	// 9. Initial OS Fallback
	if input.InitialOS != "" && input.InitialOS != "Unknown" && input.InitialOS != "Linux / Unix" && input.InitialOS != "Linux / macOS / iOS / Android" && input.InitialOS != "Unknown OS" {
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
		return OSScoreResult{
			OS:         "",
			Confidence: "",
			Evidence:   "",
			Score:      0.0,
		}
	}

	// Confidence classification
	confidence := "low"
	if bestCandidate.score >= 0.85 || hasDecisiveEvidence(bestCandidate.reasons) {
		confidence = "high"
	} else if bestCandidate.score >= 0.4 {
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
