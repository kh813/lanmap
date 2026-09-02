package scanner

import (
	"net"
	"time"
)

// PingResult represents ping response
type PingResult struct {
	IP        net.IP
	Alive     bool
	RTT       time.Duration
	TTL       int
	ErrorHint string
}

// DetectOSByTTL estimates OS vendor from ICMP TTL
func DetectOSByTTL(ttl int) string {
	if ttl <= 0 {
		return ""
	}
	switch {
	case ttl <= 64:
		return "Linux / macOS / iOS / Android"
	case ttl <= 128:
		return "Windows"
	case ttl <= 255:
		return "Network Device / Cisco"
	default:
		return "Unknown OS"
	}
}
