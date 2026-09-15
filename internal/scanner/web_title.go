package scanner

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"
)

var titleRegexp = regexp.MustCompile(`(?i)<title[^>]*>([^<]+)</title>`)

// ExtractWebTitle probes HTTP/HTTPS ports to fetch HTML <title> or server brand banner
func ExtractWebTitle(ip string, openPorts string) string {
	ports := []int{80, 443, 8080, 8443, 5000}
	if strings.Contains(openPorts, "8000") {
		ports = append(ports, 8000)
	}
	if strings.Contains(openPorts, "8899") {
		ports = append(ports, 8899)
	}

	client := &http.Client{
		Timeout: 350 * time.Millisecond,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 2 {
				return http.ErrUseLastResponse
			}
			return nil
		},
	}

	for _, port := range ports {
		// Only probe if openPorts contains the port or if openPorts is empty (heuristic)
		portStr := fmt.Sprintf("%d", port)
		if openPorts != "" && !strings.Contains(openPorts, portStr) {
			continue
		}

		schemes := []string{"http", "https"}
		if port == 443 || port == 8443 {
			schemes = []string{"https", "http"}
		}

		for _, scheme := range schemes {
			url := fmt.Sprintf("%s://%s:%d/", scheme, ip, port)
			req, err := http.NewRequest("GET", url, nil)
			if err != nil {
				continue
			}
			req.Close = true
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) lanmap/0.0.27")

			resp, err := client.Do(req)
			if err != nil {
				continue
			}

			// Read up to first 8KB of response
			buf := make([]byte, 8192)
			n, _ := io.ReadFull(resp.Body, buf)
			serverHdr := resp.Header.Get("Server")
			resp.Body.Close()

			if n > 0 {
				body := string(buf[:n])
				matches := titleRegexp.FindStringSubmatch(body)
				if len(matches) >= 2 {
					title := strings.TrimSpace(matches[1])
					title = strings.Join(strings.Fields(title), " ")
					if title != "" && !strings.EqualFold(title, "404 Not Found") && !strings.EqualFold(title, "302 Found") && !strings.EqualFold(title, "Document Error") {
						return title
					}
				}

				// Fallback: Check HTML body for distinct equipment signatures
				bodyLower := strings.ToLower(body)
				if strings.Contains(bodyLower, "fortigate") || strings.Contains(bodyLower, "fortinet") {
					return "FortiGate Administrative WebUI"
				}
				if strings.Contains(bodyLower, "aruba instant") || strings.Contains(bodyLower, "instant on") {
					return "Aruba Instant On WebUI"
				}
				if strings.Contains(bodyLower, "netgear") {
					return "NETGEAR Management WebUI"
				}
				if strings.Contains(bodyLower, "hikvision") || strings.Contains(bodyLower, "web components") {
					return "Hikvision Web Camera"
				}
				if strings.Contains(bodyLower, "dahua") {
					return "Dahua Web Camera"
				}
			}

			// Fallback: If Server header is rich and distinct
			if serverHdr != "" {
				sLower := strings.ToLower(serverHdr)
				if strings.Contains(sLower, "uhttpd") {
					return "OpenWrt (uHTTPd)"
				}
				if strings.Contains(sLower, "synology") {
					return "Synology DSM"
				}
				if strings.Contains(sLower, "boa") || strings.Contains(sLower, "rompager") || strings.Contains(sLower, "goahead") {
					return fmt.Sprintf("Embedded Device (%s)", serverHdr)
				}
			}
		}
	}

	return ""
}
