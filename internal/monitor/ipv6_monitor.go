package monitor

import (
	"context"
	"encoding/binary"
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

// DHCPv6Packet holds extracted fields from a DHCPv6 message
type DHCPv6Packet struct {
	MessageType   byte
	TransactionID []byte
	ClientMAC     string
	AssignedIP    net.IP
	Hostname      string
}

// ParseDHCPv6Packet parses a raw DHCPv6 UDP payload
func ParseDHCPv6Packet(data []byte) (*DHCPv6Packet, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("packet too short for DHCPv6 header: %d bytes", len(data))
	}

	pkt := &DHCPv6Packet{
		MessageType:   data[0],
		TransactionID: data[1:4],
	}

	offset := 4
	for offset+4 <= len(data) {
		optCode := binary.BigEndian.Uint16(data[offset : offset+2])
		optLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4
		if offset+optLen > len(data) {
			break
		}
		optData := data[offset : offset+optLen]
		offset += optLen

		switch optCode {
		case 1: // OPTION_CLIENTID
			if mac := extractMACFromDUID(optData); mac != "" {
				pkt.ClientMAC = mac
			}
		case 3: // OPTION_IA_NA
			if len(optData) > 12 {
				subData := optData[12:]
				subOffset := 0
				for subOffset+4 <= len(subData) {
					subCode := binary.BigEndian.Uint16(subData[subOffset : subOffset+2])
					subLen := int(binary.BigEndian.Uint16(subData[subOffset+2 : subOffset+4]))
					subOffset += 4
					if subOffset+subLen > len(subData) {
						break
					}
					if subCode == 5 && subLen >= 16 { // OPTION_IAADDR
						ip := net.IP(subData[subOffset : subOffset+16])
						if ip.To4() == nil && !ip.IsUnspecified() {
							pkt.AssignedIP = ip
						}
					}
					subOffset += subLen
				}
			}
		case 39: // OPTION_CLIENT_FQDN
			if len(optData) > 1 {
				pkt.Hostname = parseDHCPv6FQDN(optData[1:])
			}
		}
	}

	return pkt, nil
}

func extractMACFromDUID(duid []byte) string {
	if len(duid) < 2 {
		return ""
	}
	duidType := binary.BigEndian.Uint16(duid[:2])
	switch duidType {
	case 1: // DUID-LLT: type(2) + hwType(2) + time(4) + linkLayerAddr
		if len(duid) >= 8+6 {
			hwType := binary.BigEndian.Uint16(duid[2:4])
			if hwType == 1 { // Ethernet
				return scanner.NormalizeMAC(net.HardwareAddr(duid[8 : 8+6]).String())
			}
		}
	case 3: // DUID-LL: type(2) + hwType(2) + linkLayerAddr
		if len(duid) >= 4+6 {
			hwType := binary.BigEndian.Uint16(duid[2:4])
			if hwType == 1 { // Ethernet
				return scanner.NormalizeMAC(net.HardwareAddr(duid[4 : 4+6]).String())
			}
		}
	}
	return ""
}

func parseDHCPv6FQDN(data []byte) string {
	var parts []string
	idx := 0
	for idx < len(data) {
		labelLen := int(data[idx])
		if labelLen == 0 {
			break
		}
		idx++
		if idx+labelLen > len(data) {
			break
		}
		parts = append(parts, string(data[idx:idx+labelLen]))
		idx += labelLen
	}
	return strings.Join(parts, ".")
}

// IPv6Monitor passively monitors DHCPv6 traffic and detects Rogue RA (Router Advertisements)
type IPv6Monitor struct {
	db          *db.DB
	notifier    *notifier.Notifier
	mu          sync.Mutex
	seenTime    map[string]time.Time
	rogueAlerts map[string]time.Time // rogue MAC -> last alerted time
}

// NewIPv6Monitor creates a new passive IPv6 monitor
func NewIPv6Monitor(database *db.DB, notif *notifier.Notifier) *IPv6Monitor {
	return &IPv6Monitor{
		db:          database,
		notifier:    notif,
		seenTime:    make(map[string]time.Time),
		rogueAlerts: make(map[string]time.Time),
	}
}

// Start launches the DHCPv6 packet listeners and Rogue RA audit background loops
func (m *IPv6Monitor) Start(ctx context.Context) {
	ports := []int{546, 547}
	for _, port := range ports {
		go m.listenUDP6(ctx, port)
	}

	go m.startRogueRAAuditLoop(ctx)
}

func (m *IPv6Monitor) listenUDP6(ctx context.Context, port int) {
	addr := &net.UDPAddr{
		IP:   net.IPv6zero,
		Port: port,
	}

	conn, err := net.ListenUDP("udp6", addr)
	if err != nil {
		log.Printf("[INFO] IPv6 Monitor: UDP port %d passive listen unavailable (%v)", port, err)
		return
	}
	defer conn.Close()

	log.Printf("[INFO] IPv6 Monitor: Listening for DHCPv6 on UDP port %d", port)

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

		if n >= 4 {
			packetCopy := make([]byte, n)
			copy(packetCopy, buf[:n])
			go m.ProcessDHCPv6Packet(packetCopy, from)
		}
	}
}

// ProcessDHCPv6Packet parses and ingests a DHCPv6 packet
func (m *IPv6Monitor) ProcessDHCPv6Packet(data []byte, from *net.UDPAddr) {
	if m.db != nil {
		_, v6Enabled, _ := m.db.GetIPVersionSettings()
		if !v6Enabled {
			return
		}
	}

	pkt, err := ParseDHCPv6Packet(data)
	if err != nil {
		return
	}

	mac := pkt.ClientMAC
	if mac == "" {
		return
	}

	m.mu.Lock()
	lastProcessed, exists := m.seenTime[mac]
	if exists && time.Since(lastProcessed) < 5*time.Second {
		m.mu.Unlock()
		return
	}
	m.seenTime[mac] = time.Now()
	m.mu.Unlock()

	var ipv6List []string
	if from != nil && from.IP != nil && from.IP.To4() == nil && !from.IP.IsUnspecified() {
		ipv6List = append(ipv6List, from.IP.String())
	}
	if pkt.AssignedIP != nil {
		ipv6List = append(ipv6List, pkt.AssignedIP.String())
	}

	mergedIPv6 := db.MergeIPv6Addresses(ipv6List...)
	vendor := scanner.LookupVendor(mac)
	now := time.Now()

	existing, _ := m.db.GetHostByMAC(mac)
	var h *db.Host
	if existing != nil {
		h = existing
		h.IPv6Addresses = db.MergeIPv6Addresses(existing.IPv6Addresses, mergedIPv6)
		h.Status = "up"
		h.LastSeen = &now
		if h.Hostname == "" && pkt.Hostname != "" {
			h.Hostname = pkt.Hostname
		}
		if h.VendorModel == "" && vendor != "" {
			h.VendorModel = vendor
		}
	} else {
		primaryIP := from.IP.String()
		if pkt.AssignedIP != nil {
			primaryIP = pkt.AssignedIP.String()
		}
		h = &db.Host{
			IP:            primaryIP,
			MACAddress:    mac,
			Hostname:      pkt.Hostname,
			VendorModel:   vendor,
			Status:        "up",
			FirstSeen:     now,
			LastSeen:      &now,
			IPv6Addresses: mergedIPv6,
		}
	}

	_, _, _ = m.db.UpsertHostOnScan(h)
	log.Printf("[INFO] IPv6 Monitor: DHCPv6 detected host MAC: %s, IPv6: %s, Hostname: %s", mac, mergedIPv6, pkt.Hostname)
}

func (m *IPv6Monitor) startRogueRAAuditLoop(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// Initial immediate audit after 5s startup
	select {
	case <-ctx.Done():
		return
	case <-time.After(5 * time.Second):
		m.AuditRogueRouters(ctx)
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.AuditRogueRouters(ctx)
		}
	}
}

// AuditRogueRouters checks the neighbor cache for any unauthorized routers advertising RA
func (m *IPv6Monitor) AuditRogueRouters(ctx context.Context) {
	if m.db != nil {
		_, v6Enabled, _ := m.db.GetIPVersionSettings()
		if !v6Enabled {
			return
		}
	}

	entries, err := scanner.GetIPv6Neighbors("")
	if err != nil {
		return
	}

	for _, e := range entries {
		if !e.IsRouter {
			continue
		}
		normMAC := scanner.NormalizeMAC(e.MAC)
		if normMAC == "" {
			continue
		}

		// Check if host is recognized/approved as router or protected host
		h, err := m.db.GetHostByMAC(normMAC)
		if err != nil || h == nil {
			// Unknown host acting as router!
			m.handleRogueRouter(ctx, normMAC, e.IP)
			continue
		}

		// Known host: if not approved and not protected, it is an unauthorized router
		if !h.IsApproved && !h.IsProtected {
			m.handleRogueRouter(ctx, normMAC, e.IP)
		}
	}
}

func (m *IPv6Monitor) handleRogueRouter(ctx context.Context, mac, ip string) {
	m.mu.Lock()
	lastAlert, exists := m.rogueAlerts[mac]
	if exists && time.Since(lastAlert) < 1*time.Hour {
		m.mu.Unlock()
		return
	}
	m.rogueAlerts[mac] = time.Now()
	m.mu.Unlock()

	log.Printf("[ALERT] 🚨 Rogue RA (不正ルーター広告) を検知! 送信元 MAC: %s, IPv6: %s", mac, ip)
	if m.notifier != nil {
		_ = m.notifier.NotifyRogueRA(ctx, mac, ip)
	}
}
