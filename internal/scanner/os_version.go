package scanner

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"
)

// DetectDetailedOS combines all available network signals to deduce exact OS name and version
func DetectDetailedOS(ip string, hostname, vendor, initialOS, mdnsModel, httpTitle, openPorts, upnpName, upnpModel string) string {
	combined := strings.ToLower(fmt.Sprintf("%s %s %s %s %s %s %s", hostname, vendor, mdnsModel, httpTitle, openPorts, upnpName, upnpModel))

	// 1. Apple Devices & OS Version Deduction
	if strings.Contains(combined, "iphone17") || strings.Contains(combined, "iphone16p") || strings.Contains(combined, "iphone 16 pro") {
		return "iOS 18 (iPhone 16 Pro)"
	}
	if strings.Contains(combined, "iphone16") || strings.Contains(combined, "iphone 15") {
		return "iOS 17 / 18 (iPhone 15)"
	}
	if strings.Contains(combined, "iphone15") || strings.Contains(combined, "iphone 14") {
		return "iOS 16 / 17 (iPhone 14)"
	}
	if strings.Contains(combined, "iphone") {
		return "iOS (Apple iPhone)"
	}
	if strings.Contains(combined, "ipad16") || strings.Contains(combined, "m4") {
		return "iPadOS 18 (iPad Pro M4)"
	}
	if strings.Contains(combined, "ipad14") || strings.Contains(combined, "ipad") {
		return "iPadOS 17 / 18 (Apple iPad)"
	}
	if strings.Contains(combined, "m1 max") || strings.Contains(combined, "mbpm1m") || strings.Contains(combined, "macbookpro18,4") || strings.Contains(combined, "macbookpro18,2") {
		return "macOS 15 (Apple M1 Max)"
	}
	if strings.Contains(combined, "macbookpro18") || strings.Contains(combined, "m1 pro") || strings.Contains(combined, "mbpm1p") {
		return "macOS 15 (Apple M1 Pro)"
	}
	if strings.Contains(combined, "mac16") || strings.Contains(combined, "m4 pro") {
		return "macOS 15 (Apple M4)"
	}
	if strings.Contains(combined, "mac15") || strings.Contains(combined, "m3") {
		return "macOS 14 / 15 (Apple M3)"
	}
	if strings.Contains(combined, "mac14") || strings.Contains(combined, "m2") {
		return "macOS 14 (Apple M2)"
	}
	if strings.Contains(combined, "macbook") || strings.Contains(combined, "imac") || strings.Contains(combined, "mac-mini") || strings.Contains(combined, "mac.") {
		return "macOS (Apple Silicon / Mac)"
	}
	if strings.Contains(combined, "watch") {
		return "watchOS (Apple Watch)"
	}
	if strings.Contains(combined, "homepod") {
		return "HomePod OS (Apple Audio)"
	}

	// 2. SSH Banner (Port 22) Exact Linux Distro & Version
	if strings.Contains(openPorts, "22") {
		if banner := probeSSHBanner(ip, 80*time.Millisecond); banner != "" {
			if strings.Contains(banner, "Ubuntu-3ubuntu13") || strings.Contains(banner, "Ubuntu-1ubuntu") {
				return "Ubuntu 24.04 LTS (Noble)"
			}
			if strings.Contains(banner, "Ubuntu-3ubuntu0") || strings.Contains(banner, "Ubuntu-1ubuntu0") {
				return "Ubuntu 22.04 LTS (Jammy)"
			}
			if strings.Contains(banner, "Ubuntu-4ubuntu0") || strings.Contains(banner, "Ubuntu-2ubuntu0") {
				return "Ubuntu 20.04 LTS (Focal)"
			}
			if strings.Contains(banner, "Ubuntu") {
				return "Ubuntu Linux"
			}
			if strings.Contains(banner, "Debian-5+deb12") {
				return "Debian 12 (Bookworm)"
			}
			if strings.Contains(banner, "Debian-5+deb11") {
				return "Debian 11 (Bullseye)"
			}
			if strings.Contains(banner, "Debian-5+deb10") {
				return "Debian 10 (Buster)"
			}
			if strings.Contains(banner, "Raspbian") {
				return "Raspberry Pi OS (Debian)"
			}
			if strings.Contains(banner, "dropbear") {
				return "OpenWrt Linux (dropbear)"
			}
		}
	}

	// 3. Web Titles & HTTP Headers (Router, NAS, Hypervisor)
	if strings.Contains(combined, "luci 24") || strings.Contains(combined, "openwrt 24") {
		return "OpenWrt 24.10 (Linux)"
	}
	if strings.Contains(combined, "luci 23") || strings.Contains(combined, "openwrt 23") {
		return "OpenWrt 23.05 (Linux)"
	}
	if strings.Contains(combined, "openwrt") || strings.Contains(combined, "luci") {
		return "OpenWrt (Linux Router)"
	}
	if strings.Contains(combined, "synology") || strings.Contains(combined, "dsm") {
		return "Synology DSM 7.x (Linux)"
	}
	if strings.Contains(combined, "proxmox") {
		return "Proxmox VE (Debian Linux)"
	}
	if strings.Contains(combined, "truenas") {
		return "TrueNAS SCALE (Linux)"
	}

	// 4. Windows SMB & UPnP Build Number
	if strings.Contains(openPorts, "445") || strings.Contains(combined, "windows") || strings.Contains(combined, "microsoft") {
		if strings.Contains(combined, "server") {
			return "Windows Server"
		}
		if initialOS == "Windows" || strings.Contains(combined, "win") {
			return "Windows 11 / 10"
		}
	}

	// 5. IoT & Smart Home
	if strings.Contains(combined, "google-home") || strings.Contains(combined, "google home") || strings.Contains(combined, "nest") {
		return "Google Cast OS"
	}
	if strings.Contains(combined, "fold5") || strings.Contains(combined, "galaxy") || strings.Contains(combined, "samsung") {
		return "Android (Samsung One UI)"
	}
	if strings.Contains(combined, "pixel") || strings.Contains(combined, "android") {
		return "Android OS"
	}
	if strings.Contains(combined, "espressif") || strings.Contains(combined, "esp32") || strings.Contains(combined, "esp8266") {
		return "FreeRTOS (ESP-IDF)"
	}

	// 6. Fallback to initialOS if already descriptive
	if initialOS != "" && initialOS != "Unknown" {
		return initialOS
	}

	return "Linux / Unix"
}

func probeSSHBanner(ip string, timeout time.Duration) string {
	conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "22"), timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))
	reader := bufio.NewReader(conn)
	banner, err := reader.ReadString('\n')
	if err != nil {
		return ""
	}
	return strings.TrimSpace(banner)
}
