package scanner

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"time"
)

// DetectDetailedOS combines verified network signals (mDNS model signatures, SSH banners, HTTP headers, UPnP) to deduce exact OS
func DetectDetailedOS(ip string, hostname, vendor, initialOS, mdnsModel, httpTitle, openPorts, upnpName, upnpModel string) string {
	// Notice: We strictly DO NOT include arbitrary user hostnames in the evidence string
	evidence := strings.ToLower(fmt.Sprintf("%s %s %s %s %s", mdnsModel, httpTitle, openPorts, upnpName, upnpModel))

	// 1. Evidence from verified mDNS Model Signatures (e.g. MacBookPro18,4, iPhone17,1)
	if strings.Contains(mdnsModel, "MacBook") || strings.Contains(mdnsModel, "Mac mini") || strings.Contains(mdnsModel, "Mac Studio") || strings.Contains(mdnsModel, "iMac") {
		return "macOS (Apple Silicon)"
	}
	if strings.Contains(mdnsModel, "iPhone") {
		return "iOS (Apple iPhone)"
	}
	if strings.Contains(mdnsModel, "iPad") {
		return "iPadOS (Apple iPad)"
	}
	if strings.Contains(mdnsModel, "Apple TV") {
		return "tvOS (Apple TV)"
	}
	if strings.Contains(mdnsModel, "HomePod") {
		return "HomePod OS"
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
	if strings.Contains(evidence, "luci 24") || strings.Contains(evidence, "openwrt 24") {
		return "OpenWrt 24.10 (Linux)"
	}
	if strings.Contains(evidence, "luci 23") || strings.Contains(evidence, "openwrt 23") {
		return "OpenWrt 23.05 (Linux)"
	}
	if strings.Contains(evidence, "openwrt") || strings.Contains(evidence, "luci") {
		return "OpenWrt (Linux Router)"
	}
	if strings.Contains(evidence, "synology") || strings.Contains(evidence, "dsm") {
		return "Synology DSM 7.x (Linux)"
	}
	if strings.Contains(evidence, "proxmox") {
		return "Proxmox VE (Debian Linux)"
	}
	if strings.Contains(evidence, "truenas") {
		return "TrueNAS SCALE (Linux)"
	}

	// 4. Windows SMB & UPnP
	if strings.Contains(openPorts, "445") || strings.Contains(evidence, "windows") || strings.Contains(evidence, "microsoft") {
		if strings.Contains(evidence, "server") {
			return "Windows Server"
		}
		if initialOS == "Windows" || strings.Contains(evidence, "win") {
			return "Windows 11 / 10"
		}
	}

	// 5. IoT & Smart Home
	if strings.Contains(evidence, "google-home") || strings.Contains(evidence, "google home") || strings.Contains(evidence, "nest") {
		return "Google Cast OS"
	}
	if strings.Contains(evidence, "galaxy") || strings.Contains(evidence, "samsung") {
		return "Android (Samsung One UI)"
	}
	if strings.Contains(evidence, "pixel") || strings.Contains(evidence, "android") {
		return "Android OS"
	}
	if strings.Contains(evidence, "espressif") || strings.Contains(evidence, "esp32") || strings.Contains(evidence, "esp8266") {
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
