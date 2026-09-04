package monitor

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"lanmap/internal/db"
	"lanmap/internal/notifier"
	"lanmap/internal/scanner"
)

// DHCPMagicCookie is the standard 4-byte magic cookie starting DHCP options (99.130.83.99)
var DHCPMagicCookie = []byte{0x63, 0x82, 0x53, 0x63}

// DHCPPacket represents parsed DHCP/BOOTP packet fields
type DHCPPacket struct {
	Op          byte     // 1 = BOOTREQUEST, 2 = BOOTREPLY
	HType       byte     // Hardware type (1 = 10Mb Ethernet)
	HLen        byte     // Hardware address length (6 for MAC)
	XID         uint32   // Transaction ID
	CIAddr      net.IP   // Client IP (renewal)
	YIAddr      net.IP   // Your IP (assigned by server)
	GIAddr      net.IP   // Relay agent IP
	CHAddr      string   // Client hardware MAC address (lowercase formatted)
	MessageType byte     // Option 53: 1=DISCOVER, 2=OFFER, 3=REQUEST, 5=ACK, etc.
	RequestedIP net.IP   // Option 50
	Hostname    string   // Option 12
	VendorClass string   // Option 60
	ParamList   []byte   // Option 55
}

// DHCPMonitor passively listens for DHCP broadcast traffic on UDP ports 67 and 68
type DHCPMonitor struct {
	db       *db.DB
	notifier *notifier.Notifier
	mu       sync.Mutex
	seenTime map[string]time.Time // key (IP+MAC) -> last processed time
}

// NewDHCPMonitor creates a new passive DHCP monitor
func NewDHCPMonitor(database *db.DB, notif *notifier.Notifier) *DHCPMonitor {
	return &DHCPMonitor{
		db:       database,
		notifier: notif,
		seenTime: make(map[string]time.Time),
	}
}

// Start launches the DHCP packet listeners in background goroutines
func (m *DHCPMonitor) Start(ctx context.Context) {
	ports := []int{67, 68}
	for _, port := range ports {
		go m.listenUDP(ctx, port)
	}
}

func (m *DHCPMonitor) listenUDP(ctx context.Context, port int) {
	addr := &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: port,
	}

	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		log.Printf("[INFO] DHCP Monitor: Port %d passive listen unavailable (%v)", port, err)
		return
	}
	defer conn.Close()

	log.Printf("[INFO] DHCP Monitor: Listening for DHCP broadcasts on UDP port %d", port)

	buf := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		_ = conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}

		if n >= 240 {
			packetCopy := make([]byte, n)
			copy(packetCopy, buf[:n])
			go m.ProcessPacket(packetCopy, from)
		}
	}
}

// ParseDHCPPacket parses a raw BOOTP/DHCP datagram
func ParseDHCPPacket(data []byte) (*DHCPPacket, error) {
	if len(data) < 240 {
		return nil, errors.New("DHCP packet too short")
	}

	// Verify Magic Cookie (offset 236..239)
	if !bytes.Equal(data[236:240], DHCPMagicCookie) {
		return nil, errors.New("invalid or missing DHCP magic cookie")
	}

	pkt := &DHCPPacket{
		Op:    data[0],
		HType: data[1],
		HLen:  data[2],
		XID:   binary.BigEndian.Uint32(data[4:8]),
	}

	ci := net.IPv4(data[12], data[13], data[14], data[15])
	if !ci.IsUnspecified() {
		pkt.CIAddr = ci
	}

	yi := net.IPv4(data[16], data[17], data[18], data[19])
	if !yi.IsUnspecified() {
		pkt.YIAddr = yi
	}

	gi := net.IPv4(data[24], data[25], data[26], data[27])
	if !gi.IsUnspecified() {
		pkt.GIAddr = gi
	}

	// Client MAC address from chaddr (offset 28..43)
	if pkt.HType == 1 && pkt.HLen == 6 && len(data) >= 34 {
		mac := net.HardwareAddr(data[28:34])
		pkt.CHAddr = strings.ToLower(mac.String())
	}

	// Parse Options starting from offset 240
	offset := 240
	for offset < len(data) {
		tag := data[offset]
		if tag == 0 { // PAD
			offset++
			continue
		}
		if tag == 255 { // END
			break
		}
		if offset+1 >= len(data) {
			break
		}
		optLen := int(data[offset+1])
		if offset+2+optLen > len(data) {
			break
		}
		optData := data[offset+2 : offset+2+optLen]

		switch tag {
		case 53: // DHCP Message Type
			if len(optData) >= 1 {
				pkt.MessageType = optData[0]
			}
		case 50: // Requested IP Address
			if len(optData) == 4 {
				reqIP := net.IPv4(optData[0], optData[1], optData[2], optData[3])
				if !reqIP.IsUnspecified() {
					pkt.RequestedIP = reqIP
				}
			}
		case 12: // Host Name
			pkt.Hostname = cleanString(optData)
		case 60: // Vendor Class Identifier
			pkt.VendorClass = cleanString(optData)
		case 55: // Parameter Request List
			pkt.ParamList = append([]byte(nil), optData...)
		case 81: // Client FQDN
			if pkt.Hostname == "" && len(optData) > 3 {
				// Byte 0: flags, Byte 1: rcode1, Byte 2: rcode2, Byte 3+: FQDN
				fqdn := cleanString(optData[3:])
				if fqdn != "" {
					// Extract first part if domain is appended
					parts := strings.Split(fqdn, ".")
					if len(parts) > 0 && parts[0] != "" {
						pkt.Hostname = parts[0]
					}
				}
			}
		}

		offset += 2 + optLen
	}

	return pkt, nil
}

func cleanString(b []byte) string {
	s := strings.TrimRight(string(b), "\x00 \t\r\n")
	return strings.ToValidUTF8(s, "")
}

// ProcessPacket handles an incoming raw DHCP packet
func (m *DHCPMonitor) ProcessPacket(data []byte, from *net.UDPAddr) {
	pkt, err := ParseDHCPPacket(data)
	if err != nil {
		return
	}

	if pkt.CHAddr == "" {
		return
	}

	// Resolve the target IP address
	// Preference: 1. yiaddr (assigned), 2. requested IP (Option 50), 3. ciaddr (renewing)
	var targetIP net.IP
	if pkt.YIAddr != nil && !pkt.YIAddr.IsUnspecified() && !pkt.YIAddr.IsLoopback() {
		targetIP = pkt.YIAddr
	} else if pkt.RequestedIP != nil && !pkt.RequestedIP.IsUnspecified() && !pkt.RequestedIP.IsLoopback() {
		targetIP = pkt.RequestedIP
	} else if pkt.CIAddr != nil && !pkt.CIAddr.IsUnspecified() && !pkt.CIAddr.IsLoopback() {
		targetIP = pkt.CIAddr
	}

	if targetIP == nil || targetIP.IsUnspecified() || targetIP.IsLoopback() {
		return
	}

	ipStr := targetIP.String()

	// Debounce: don't process redundant packets from same (IP, MAC) within 15 seconds
	m.mu.Lock()
	debounceKey := ipStr + "@" + pkt.CHAddr
	if last, exists := m.seenTime[debounceKey]; exists && time.Since(last) < 15*time.Second {
		m.mu.Unlock()
		return
	}
	m.seenTime[debounceKey] = time.Now()

	// Clean up older debounce cache entries
	cutoff := time.Now().Add(-5 * time.Minute)
	for k, t := range m.seenTime {
		if t.Before(cutoff) {
			delete(m.seenTime, k)
		}
	}
	m.mu.Unlock()

	// 1. Determine vendor from OUI
	vendor := scanner.LookupVendor(pkt.CHAddr)

	// 2. Infer OS from Option 60 (Vendor Class Identifier) and Option 55
	osVendor := InferOSFromDHCP(pkt.VendorClass, pkt.ParamList)

	// 3. Find Segment
	seg, _ := m.db.FindSegmentForIP(targetIP)
	var segID *int64
	if seg != nil {
		segID = &seg.ID
	}

	// 4. Check Whitelist
	isApproved := false
	displayName := ""
	if wlMatch, ok := m.db.MatchWhitelist(pkt.Hostname, pkt.CHAddr); ok {
		isApproved = true
		if wlMatch.DeviceName != "" {
			displayName = wlMatch.DeviceName
		} else {
			displayName = wlMatch.Hostname
		}
	}

	hostObj := &db.Host{
		IP:          ipStr,
		SegmentID:   segID,
		MACAddress:  pkt.CHAddr,
		Hostname:    pkt.Hostname,
		DisplayName: displayName,
		VendorModel: vendor,
		OSVendor:    osVendor,
		Status:      "up",
		IsDHCP:      true,
		IsApproved:  isApproved,
	}

	isNew, isReplaced, err := m.db.UpsertHostOnScan(hostObj)
	if err != nil {
		log.Printf("[WARN] DHCP Monitor: Failed to upsert host %s: %v", ipStr, err)
		return
	}

	msgTypeStr := formatDHCPMessageType(pkt.MessageType)
	log.Printf("[INFO] ⚡ DHCP Monitor: %s from %s (MAC: %s, Host: %q, Vendor: %q, OS: %q, New: %v)",
		msgTypeStr, ipStr, pkt.CHAddr, pkt.Hostname, vendor, osVendor, isNew || isReplaced)

	// Auto-adjust segment DHCP range if not manual
	if seg != nil && !seg.IsDHCPManual {
		_, _ = m.db.AutoAdjustSegmentDHCPRange(seg.ID)
	}

	// Trigger alert if new or replaced unapproved host
	if (isNew || isReplaced) && !isApproved {
		savedHost, err := m.db.GetHost(ipStr)
		if err == nil && savedHost != nil && !savedHost.IsApproved {
			log.Printf("[WARN] 🚨 DHCP Monitor: Unapproved host %s (%s) detected via DHCP! Sending alert...", ipStr, pkt.CHAddr)
			go func() {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				_ = m.notifier.NotifyUnapprovedHosts(ctx, []*db.Host{savedHost})
			}()
		}
	}
}

// InferOSFromDHCP infers the operating system from DHCP Option 60 and Option 55
func InferOSFromDHCP(vendorClass string, paramList []byte) string {
	vc := strings.ToLower(vendorClass)

	// Check Option 60 Vendor Class Identifier
	if strings.Contains(vc, "msft") {
		return "Windows"
	}
	if strings.Contains(vc, "android") {
		return "Android"
	}
	if strings.Contains(vc, "apple") || strings.Contains(vc, "darwin") {
		return "macOS/iOS"
	}
	if strings.Contains(vc, "dhcpcd") || strings.Contains(vc, "udhcp") || strings.Contains(vc, "networkmanager") {
		return "Linux"
	}
	if strings.Contains(vc, "printer") || strings.Contains(vc, "canon") || strings.Contains(vc, "epson") || strings.Contains(vc, "brother") {
		return "Printer"
	}
	if strings.Contains(vc, "cisco") {
		return "Cisco Network Device"
	}

	// Check Option 55 Parameter Request List Fingerprints
	if len(paramList) > 0 {
		// Windows typical parameter sequence contains 1, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252
		if containsSubsequence(paramList, []byte{1, 3, 6, 15, 31, 33, 43, 44, 46, 47}) ||
			containsSubsequence(paramList, []byte{1, 15, 3, 6, 44, 46, 47, 31, 33, 121, 249, 43}) {
			return "Windows"
		}
		// Apple typical parameter sequence (iOS / macOS)
		if bytes.Equal(paramList, []byte{1, 121, 3, 6, 15, 119, 252}) ||
			bytes.Equal(paramList, []byte{1, 3, 6, 15, 119, 252}) {
			return "macOS/iOS"
		}
	}

	return ""
}

func containsSubsequence(data, sub []byte) bool {
	return bytes.Contains(data, sub)
}

func formatDHCPMessageType(t byte) string {
	switch t {
	case 1:
		return "DHCPDISCOVER"
	case 2:
		return "DHCPOFFER"
	case 3:
		return "DHCPREQUEST"
	case 4:
		return "DHCPDECLINE"
	case 5:
		return "DHCPACK"
	case 6:
		return "DHCPNAK"
	case 7:
		return "DHCPRELEASE"
	case 8:
		return "DHCPINFORM"
	default:
		return fmt.Sprintf("DHCP (type %d)", t)
	}
}
