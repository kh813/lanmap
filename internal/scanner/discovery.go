package scanner

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// GetAllARPEntries reads and parses the full system ARP cache into a map[IP]MAC
func GetAllARPEntries() map[string]string {
	arpMap := make(map[string]string)

	if runtime.GOOS == "linux" {
		f, err := os.Open("/proc/net/arp")
		if err == nil {
			defer f.Close()
			scanner := bufio.NewScanner(f)
			for scanner.Scan() {
				fields := strings.Fields(scanner.Text())
				if len(fields) >= 4 {
					ip := fields[0]
					mac := fields[3]
					if mac != "00:00:00:00:00:00" && !strings.Contains(mac, "incomplete") {
						arpMap[ip] = normalizeMAC(mac)
					}
				}
			}
			return arpMap
		}
	}

	// macOS / BSD / Windows fallback
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "arp", "-a")
	} else {
		cmd = exec.CommandContext(ctx, "arp", "-an")
	}

	out, err := cmd.Output()
	if err != nil {
		return arpMap
	}

	// Regex for "(192.168.3.1) at 38:97:a4:4f:84:60" or "192.168.3.1  38-97-a4-4f-84-60"
	lineScanner := bufio.NewScanner(bytes.NewReader(out))
	ipRegex := regexp.MustCompile(`(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})`)
	macRegex := regexp.MustCompile(`([0-9a-fA-F]{1,2}[:-]){5}([0-9a-fA-F]{1,2})`)

	for lineScanner.Scan() {
		line := lineScanner.Text()
		if strings.Contains(line, "incomplete") {
			continue
		}
		ipMatch := ipRegex.FindString(line)
		macMatch := macRegex.FindString(line)
		if ipMatch != "" && macMatch != "" {
			if macMatch != "ff:ff:ff:ff:ff:ff" && macMatch != "00:00:00:00:00:00" {
				arpMap[ipMatch] = normalizeMAC(macMatch)
			}
		}
	}

	return arpMap
}

// ResolveMAC attempts to find MAC address for an IP from the system ARP cache
func ResolveMAC(ip string) string {
	arpMap := GetAllARPEntries()
	if mac, ok := arpMap[ip]; ok {
		return mac
	}

	if runtime.GOOS == "linux" {
		if mac := readLinuxARP(ip); mac != "" {
			return mac
		}
	}

	return execARPCommand(ip)
}

func readLinuxARP(targetIP string) string {
	f, err := os.Open("/proc/net/arp")
	if err != nil {
		return ""
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 4 {
			ip := fields[0]
			mac := fields[3]
			if ip == targetIP && mac != "00:00:00:00:00:00" {
				return normalizeMAC(mac)
			}
		}
	}
	return ""
}

func execARPCommand(targetIP string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "arp", "-a", targetIP)
	} else {
		cmd = exec.CommandContext(ctx, "arp", "-n", targetIP)
	}

	out, err := cmd.Output()
	if err != nil {
		return ""
	}

	macRegex := regexp.MustCompile(`([0-9a-fA-F]{1,2}[:-]){5}([0-9a-fA-F]{1,2})`)
	match := macRegex.FindString(string(out))
	if match != "" && match != "00:00:00:00:00:00" && match != "ff:ff:ff:ff:ff:ff" {
		return normalizeMAC(match)
	}
	return ""
}

func normalizeMAC(mac string) string {
	mac = strings.ToLower(strings.TrimSpace(mac))
	parts := strings.FieldsFunc(mac, func(r rune) bool {
		return r == ':' || r == '-' || r == '.'
	})
	if len(parts) == 6 {
		var norm []string
		for _, p := range parts {
			if len(p) == 1 {
				norm = append(norm, "0"+p)
			} else {
				norm = append(norm, p)
			}
		}
		return strings.Join(norm, ":")
	}
	return mac
}

// ResolveHostname attempts reverse DNS and NBNS
func ResolveHostname(ipStr string, timeout time.Duration) string {
	// 1. Reverse DNS (PTR)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var r net.Resolver
	names, err := r.LookupAddr(ctx, ipStr)
	if err == nil && len(names) > 0 {
		name := strings.TrimSuffix(names[0], ".")
		if name != "" && name != ipStr {
			return name
		}
	}

	// 2. NetBIOS Name Service (NBNS) query for Windows / Samba hosts
	if nbName := QueryNBNS(ipStr, 300*time.Millisecond); nbName != "" {
		return nbName
	}

	return ""
}

// QueryNBNS sends a NetBIOS node status query (port 137) to get computer name
func QueryNBNS(ipStr string, timeout time.Duration) string {
	addr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(ipStr, "137"))
	if err != nil {
		return ""
	}

	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		return ""
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(timeout))

	packet := []byte{
		0x12, 0x34, // Transaction ID
		0x00, 0x00, // Flags: standard query
		0x00, 0x01, // Questions: 1
		0x00, 0x00, // Answer RRs: 0
		0x00, 0x00, // Authority RRs: 0
		0x00, 0x00, // Additional RRs: 0
		0x20,       // Length of name (32)
		'C', 'K', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
		'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
		'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A', 'A',
		'A', 'A',
		0x00,       // Terminator
		0x00, 0x21, // Type: NBSTAT
		0x00, 0x01, // Class: IN
	}

	if _, err := conn.Write(packet); err != nil {
		return ""
	}

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil || n < 56 {
		return ""
	}

	numNames := int(buf[56])
	offset := 57
	for i := 0; i < numNames && offset+18 <= n; i++ {
		rawName := string(bytes.TrimSpace(buf[offset : offset+15]))
		nameType := buf[offset+15]
		flags := binary.BigEndian.Uint16(buf[offset+16 : offset+18])

		isGroup := (flags & 0x8000) != 0
		if !isGroup && (nameType == 0x00 || nameType == 0x20) {
			cleanName := strings.TrimSpace(rawName)
			if cleanName != "" {
				return cleanName
			}
		}
		offset += 18
	}

	return ""
}
