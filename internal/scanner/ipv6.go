package scanner

import (
	"context"
	"fmt"
	"log"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"lanmap/internal/db"
)

// NeighborEntry represents an IPv6 neighbor entry from the OS neighbor cache / NDP table
type NeighborEntry struct {
	IP        string
	MAC       string
	Interface string
	IsRouter  bool
	State     string
}

// NormalizeMAC normalizes MAC address formatting: lowercase, colon-separated,
// and ensures single-digit octets (common in BSD/macOS ndp output) are padded to 2 hex characters.
func NormalizeMAC(mac string) string {
	return normalizeMAC(mac)
}

// ParseNDPOutput parses the output of `ndp -an` on macOS and BSD systems.
// Line format example:
// 240b:10:... 8a:22:c1:5c:85:f7 en0 17h38m25s S
// fe80::...%en0 38:97:a4:4f:84:60 en0 2m17s R R
func ParseNDPOutput(output string) []NeighborEntry {
	var entries []NeighborEntry
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		ipStr := fields[0]
		macStr := fields[1]
		if macStr == "(incomplete)" || macStr == "(none)" {
			continue
		}
		normMAC := NormalizeMAC(macStr)
		if _, err := net.ParseMAC(normMAC); err != nil {
			continue
		}

		cleanIP := ipStr
		if idx := strings.Index(cleanIP, "%"); idx != -1 {
			cleanIP = cleanIP[:idx]
		}
		ip := net.ParseIP(cleanIP)
		if ip == nil || ip.To4() != nil {
			continue
		}

		if fields[3] == "expired" {
			continue
		}

		netif := fields[2]
		state := ""
		if len(fields) >= 5 {
			state = fields[4]
		}
		isRouter := false
		if len(fields) >= 6 {
			for _, flg := range fields[5:] {
				if flg == "R" {
					isRouter = true
					break
				}
			}
		}

		entries = append(entries, NeighborEntry{
			IP:        cleanIP,
			MAC:       normMAC,
			Interface: netif,
			IsRouter:  isRouter,
			State:     state,
		})
	}
	return entries
}

// ParseIPNeighOutput parses the output of `ip -6 neigh show` on Linux systems.
// Line format example:
// fe80::211:22ff:fe33:4455 dev eth0 lladdr 00:11:22:33:44:55 router REACHABLE
// 2001:db8::50 dev eth0 lladdr 00:11:22:33:44:55 STALE
func ParseIPNeighOutput(output string) []NeighborEntry {
	var entries []NeighborEntry
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		cleanIP := fields[0]
		if idx := strings.Index(cleanIP, "%"); idx != -1 {
			cleanIP = cleanIP[:idx]
		}
		ip := net.ParseIP(cleanIP)
		if ip == nil || ip.To4() != nil {
			continue
		}

		var dev, mac, state string
		var isRouter bool

		for i := 1; i < len(fields); i++ {
			switch fields[i] {
			case "dev":
				if i+1 < len(fields) {
					dev = fields[i+1]
					i++
				}
			case "lladdr":
				if i+1 < len(fields) {
					mac = fields[i+1]
					i++
				}
			case "router":
				isRouter = true
			default:
				state = fields[i]
			}
		}

		if mac == "" {
			continue
		}
		if state == "FAILED" || state == "INCOMPLETE" {
			continue
		}
		normMAC := NormalizeMAC(mac)
		if _, err := net.ParseMAC(normMAC); err != nil {
			continue
		}

		entries = append(entries, NeighborEntry{
			IP:        cleanIP,
			MAC:       normMAC,
			Interface: dev,
			IsRouter:  isRouter,
			State:     state,
		})
	}
	return entries
}

// ParseWindowsNeighOutput parses the output of `netsh interface ipv6 show neighbors` on Windows.
// Line format example:
// fe80::1 00-11-22-33-44-55 Reachable
func ParseWindowsNeighOutput(output string) []NeighborEntry {
	var entries []NeighborEntry
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		cleanIP := fields[0]
		if idx := strings.Index(cleanIP, "%"); idx != -1 {
			cleanIP = cleanIP[:idx]
		}
		ip := net.ParseIP(cleanIP)
		if ip == nil || ip.To4() != nil {
			continue
		}

		normMAC := NormalizeMAC(fields[1])
		if _, err := net.ParseMAC(normMAC); err != nil {
			continue
		}

		state := fields[2]
		if strings.EqualFold(state, "Unreachable") {
			continue
		}

		entries = append(entries, NeighborEntry{
			IP:    cleanIP,
			MAC:   normMAC,
			State: state,
		})
	}
	return entries
}

// GetIPv6Neighbors returns all active IPv6 neighbors from the OS cache, optionally filtered by interface.
func GetIPv6Neighbors(iface string) ([]NeighborEntry, error) {
	switch runtime.GOOS {
	case "darwin", "freebsd", "openbsd", "netbsd":
		cmd := exec.Command("ndp", "-an")
		out, err := cmd.Output()
		if err != nil {
			return nil, err
		}
		entries := ParseNDPOutput(string(out))
		if iface != "" {
			var filtered []NeighborEntry
			for _, e := range entries {
				if e.Interface == iface {
					filtered = append(filtered, e)
				}
			}
			return filtered, nil
		}
		return entries, nil
	case "linux":
		args := []string{"-6", "neigh", "show"}
		if iface != "" {
			args = append(args, "dev", iface)
		}
		cmd := exec.Command("ip", args...)
		out, err := cmd.Output()
		if err != nil {
			return nil, err
		}
		return ParseIPNeighOutput(string(out)), nil
	case "windows":
		cmd := exec.Command("netsh", "interface", "ipv6", "show", "neighbors")
		out, err := cmd.Output()
		if err != nil {
			return nil, err
		}
		return ParseWindowsNeighOutput(string(out)), nil
	default:
		return nil, fmt.Errorf("unsupported OS for IPv6 neighbor discovery: %s", runtime.GOOS)
	}
}

// SendAllNodesMulticastPing broadcasts an ICMPv6 Echo Request to ff02::1 (All Nodes)
// on the specified interface to trigger neighbor discovery responses without flooding the network.
func SendAllNodesMulticastPing(ctx context.Context, iface string) error {
	switch runtime.GOOS {
	case "darwin", "freebsd", "openbsd", "netbsd":
		target := "ff02::1"
		if iface != "" {
			target = "ff02::1%" + iface
		}
		cmd := exec.CommandContext(ctx, "ping6", "-c", "1", "-W", "500", target)
		_ = cmd.Run()
	case "linux":
		args := []string{"-6", "-c", "1", "-W", "1"}
		if iface != "" {
			args = append(args, "-I", iface)
		}
		args = append(args, "ff02::1")
		cmd := exec.CommandContext(ctx, "ping", args...)
		_ = cmd.Run()
	case "windows":
		target := "ff02::1"
		if iface != "" {
			target = "ff02::1%" + iface
		}
		cmd := exec.CommandContext(ctx, "ping", "-6", "-n", "1", target)
		_ = cmd.Run()
	}
	return nil
}

// ScanIPv6Segment performs IPv6 discovery for a network segment:
// 1. Sends All-Nodes Multicast Ping (ff02::1) on the segment's interface to prompt neighbor replies.
// 2. Polls OS neighbor cache (NDP table) for active neighbors.
// 3. Groups discovered IPv6 addresses by MAC address.
// 4. Upserts hosts into DB using MAC-based dual-stack aggregation.
func ScanIPv6Segment(ctx context.Context, seg *db.Segment, database *db.DB) ([]*ScanReport, error) {
	iface := seg.InterfaceName
	if iface == "" {
		if netIf, err := GetDefaultInterface(); err == nil && netIf != nil {
			iface = netIf.Name
		}
	}

	// 1. Send multicast ping
	_ = SendAllNodesMulticastPing(ctx, iface)

	// Short wait for responses to register in neighbor table
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(300 * time.Millisecond):
	}

	// 2. Query neighbor cache
	entries, err := GetIPv6Neighbors(iface)
	if err != nil {
		return nil, fmt.Errorf("failed to get IPv6 neighbors: %w", err)
	}

	// 3. Group by MAC
	macMap := make(map[string][]string)
	for _, e := range entries {
		normMAC := NormalizeMAC(e.MAC)
		if normMAC == "" {
			continue
		}
		macMap[normMAC] = append(macMap[normMAC], e.IP)
	}

	var reports []*ScanReport
	now := time.Now()

	for mac, addrs := range macMap {
		select {
		case <-ctx.Done():
			return reports, ctx.Err()
		default:
		}

		mergedIPv6 := db.MergeIPv6Addresses(addrs...)
		if mergedIPv6 == "" {
			continue
		}

		existing, err := database.GetHostByMAC(mac)
		if err != nil {
			continue
		}

		vendor := LookupVendor(mac)

		var h *db.Host
		if existing != nil {
			h = existing
			h.IPv6Addresses = db.MergeIPv6Addresses(existing.IPv6Addresses, mergedIPv6)
			h.Status = "up"
			h.LastSeen = &now
			if h.VendorModel == "" && vendor != "" {
				h.VendorModel = vendor
			}
		} else {
			// Pure IPv6 host (or first seen on IPv6)
			primaryIP := addrs[0]
			for _, a := range addrs {
				c := db.ClassifyIPv6(a)
				if c.Type == db.IPv6TypeGUA || c.Type == db.IPv6TypeULA {
					primaryIP = a
					break
				}
			}
			h = &db.Host{
				IP:            primaryIP,
				SegmentID:     &seg.ID,
				MACAddress:    mac,
				VendorModel:   vendor,
				Status:        "up",
				FirstSeen:     now,
				LastSeen:      &now,
				IPv6Addresses: mergedIPv6,
			}
		}

		isNew, isReplaced, err := database.UpsertHostOnScan(h)
		if err != nil {
			log.Printf("[WARN] IPv6 Scanner: failed to upsert host %s (%s): %v", mac, mergedIPv6, err)
			continue
		}

		reports = append(reports, &ScanReport{
			Host:       h,
			IsNew:      isNew,
			IsReplaced: isReplaced,
		})
	}

	return reports, nil
}

// ScanIPv6 scans all active segments for IPv6 hosts
func (s *Scanner) ScanIPv6(ctx context.Context) ([]*ScanReport, error) {
	segments, err := s.db.ListSegments()
	if err != nil {
		return nil, fmt.Errorf("failed to list segments: %w", err)
	}

	var allReports []*ScanReport
	for _, seg := range segments {
		if !seg.IsEnabled {
			continue
		}
		select {
		case <-ctx.Done():
			return allReports, ctx.Err()
		default:
		}

		reports, err := ScanIPv6Segment(ctx, seg, s.db)
		if err != nil {
			log.Printf("[WARN] Scanner: IPv6 scan error on segment %s: %v", seg.Name, err)
			continue
		}
		allReports = append(allReports, reports...)
	}

	return allReports, nil
}
