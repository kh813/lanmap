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

// ExtractWebTitle probes HTTP/HTTPS ports to fetch HTML <title>
func ExtractWebTitle(ip string, openPorts string) string {
	ports := []int{80, 443, 8080, 8443, 5000}

	client := &http.Client{
		Timeout: 400 * time.Millisecond,
		Transport: &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		},
	}

	for _, port := range ports {
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
			req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) lanmap/0.0.5")

			resp, err := client.Do(req)
			if err != nil {
				continue
			}

			// Read up to first 8KB of response
			buf := make([]byte, 8192)
			n, _ := io.ReadFull(resp.Body, buf)
			resp.Body.Close()

			if n > 0 {
				body := string(buf[:n])
				matches := titleRegexp.FindStringSubmatch(body)
				if len(matches) >= 2 {
					title := strings.TrimSpace(matches[1])
					// Clean up newlines and excessive spaces
					title = strings.Join(strings.Fields(title), " ")
					if title != "" && !strings.EqualFold(title, "404 Not Found") && !strings.EqualFold(title, "302 Found") {
						return title
					}
				}
			}
		}
	}

	return ""
}
