package scanner

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"sync"
	"time"
)

var defaultTargetPorts = map[int]string{
	21:   "FTP",
	22:   "SSH",
	53:   "DNS",
	80:   "HTTP",
	443:  "HTTPS",
	445:  "SMB (ファイル共有)",
	548:  "AFP (Mac共有)",
	554:  "RTSP (カメラ)",
	631:  "IPP (プリンタ)",
	3389: "RDP (リモートデスクトップ)",
	5000: "AirPlay / UPnP (またはSynology)",
	5001: "Synology DSM (HTTPS)",
	7000: "AirPlay",
	8008: "Google Cast",
	8080: "HTTP-Alt",
	8443: "HTTPS-Alt",
	9100: "RAW プリンタ",
}

// ScanOpenPorts quickly and safely probes common service ports on target IP
func ScanOpenPorts(ip string, timeout time.Duration) string {
	if timeout <= 0 {
		timeout = 50 * time.Millisecond
	}

	type portResult struct {
		port    int
		service string
		open    bool
	}

	resChan := make(chan portResult, len(defaultTargetPorts))
	var wg sync.WaitGroup

	for port, service := range defaultTargetPorts {
		wg.Add(1)
		go func(p int, s string) {
			defer wg.Done()
			addr := net.JoinHostPort(ip, fmt.Sprintf("%d", p))
			conn, err := net.DialTimeout("tcp", addr, timeout)
			if err == nil {
				conn.Close()
				resChan <- portResult{port: p, service: s, open: true}
			} else {
				resChan <- portResult{port: p, service: s, open: false}
			}
		}(port, service)
	}

	wg.Wait()
	close(resChan)

	var openPorts []portResult
	for r := range resChan {
		if r.open {
			openPorts = append(openPorts, r)
		}
	}

	// Sort by port number ascending
	sort.Slice(openPorts, func(i, j int) bool {
		return openPorts[i].port < openPorts[j].port
	})

	var parts []string
	for _, op := range openPorts {
		parts = append(parts, fmt.Sprintf("%d:%s", op.port, op.service))
	}

	return strings.Join(parts, ",")
}
