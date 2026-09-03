package scanner

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"
)

// HostDetails contains refined fingerprint information
type HostDetails struct {
	RefinedHostname string
	RefinedVendor   string
	RefinedOS       string
}

// FingerprintHost attempts lightweight, non-intrusive safe fingerprinting
func FingerprintHost(ip string, initialHostname, initialVendor, initialOS string) HostDetails {
	details := HostDetails{
		RefinedHostname: initialHostname,
		RefinedVendor:   initialVendor,
		RefinedOS:       initialOS,
	}

	// 1. Probe safe common services with short timeouts (evidence-based only)
	// SSH (Port 22)
	if sshBanner := probeSSH(ip, 100*time.Millisecond); sshBanner != "" {
		if strings.Contains(sshBanner, "Ubuntu") {
			details.RefinedOS = "Linux (Ubuntu)"
		} else if strings.Contains(sshBanner, "Debian") {
			details.RefinedOS = "Linux (Debian)"
		} else if strings.Contains(sshBanner, "Raspbian") {
			details.RefinedOS = "Linux (Raspberry Pi OS)"
			details.RefinedVendor = "Raspberry Pi"
		} else if strings.Contains(sshBanner, "OpenWrt") || strings.Contains(sshBanner, "dropbear") {
			details.RefinedOS = "Linux (OpenWrt / Embedded)"
		} else if strings.Contains(sshBanner, "OpenSSH") {
			if details.RefinedOS == "" || strings.Contains(details.RefinedOS, "Unknown") {
				details.RefinedOS = "Linux / Unix (OpenSSH)"
			}
		}
	}

	// HTTP (Port 80 / 8080)
	if httpBanner := probeHTTP(ip, 100*time.Millisecond); httpBanner != "" {
		if strings.Contains(httpBanner, "uHTTPd") {
			details.RefinedOS = "Linux (OpenWrt)"
			if details.RefinedVendor == "" {
				details.RefinedVendor = "OpenWrt Router"
			}
		} else if strings.Contains(httpBanner, "synology") {
			details.RefinedOS = "Synology DSM (Linux)"
			details.RefinedVendor = "Synology NAS"
		} else if strings.Contains(httpBanner, "Microsoft-HTTPAPI") || strings.Contains(httpBanner, "IIS") {
			details.RefinedOS = "Windows Server / Windows"
			details.RefinedVendor = "Microsoft"
		}
	}

	// Apple Lockdown service (Port 62078)
	if isPortOpen(ip, 62078, 80*time.Millisecond) {
		if details.RefinedVendor == "" || strings.Contains(details.RefinedVendor, "プライベート") {
			details.RefinedVendor = "Apple"
		}
		if details.RefinedOS == "" || strings.Contains(details.RefinedOS, "Unknown") {
			details.RefinedOS = "iOS / iPadOS / macOS"
		}
	}

	// Google Cast (Port 8008)
	if isPortOpen(ip, 8008, 80*time.Millisecond) {
		if details.RefinedVendor == "" || strings.Contains(details.RefinedVendor, "プライベート") {
			details.RefinedVendor = "Google (Nest / Home)"
		}
		details.RefinedOS = "Google Cast OS"
	}

	// SMB (Port 445)
	if isPortOpen(ip, 445, 80*time.Millisecond) {
		if details.RefinedOS == "" || strings.Contains(details.RefinedOS, "Unknown") {
			details.RefinedOS = "Windows (SMB)"
		}
	}

	return details
}

func probeSSH(ip string, timeout time.Duration) string {
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

func probeHTTP(ip string, timeout time.Duration) string {
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for _, port := range []string{"80", "8080"} {
		req, err := http.NewRequestWithContext(ctx, "HEAD", fmt.Sprintf("http://%s:%s/", ip, port), nil)
		if err != nil {
			continue
		}
		req.Close = true
		resp, err := client.Do(req)
		if err == nil {
			resp.Body.Close()
			if s := resp.Header.Get("Server"); s != "" {
				return s
			}
		}
	}
	return ""
}

func isPortOpen(ip string, port int, timeout time.Duration) bool {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}
