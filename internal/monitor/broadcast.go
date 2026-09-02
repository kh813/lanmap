package monitor

import (
	"context"
	"log"
	"net"
	"sync"
	"time"

	"lanmap/internal/db"
	"lanmap/internal/notifier"
)

const (
	// StormThreshold1m is the threshold of broadcast/multicast packets in 1 minute to flag as a storm
	StormThreshold1m = 120
)

// BroadcastMonitor passively listens to LAN broadcast/multicast traffic and detects storms
type BroadcastMonitor struct {
	db          *db.DB
	notifier    *notifier.Notifier
	mu          sync.Mutex
	packetTimes map[string][]time.Time // srcIP -> list of timestamps
	storming    map[string]bool        // srcIP -> current storm state
}

// NewBroadcastMonitor creates a new broadcast monitor
func NewBroadcastMonitor(database *db.DB, notif *notifier.Notifier) *BroadcastMonitor {
	return &BroadcastMonitor{
		db:          database,
		notifier:    notif,
		packetTimes: make(map[string][]time.Time),
		storming:    make(map[string]bool),
	}
}

// Start launches the broadcast packet listeners and analysis worker
func (m *BroadcastMonitor) Start(ctx context.Context) {
	ports := []int{137, 1900, 5353}

	for _, port := range ports {
		go m.listenUDPPort(ctx, port)
	}

	go m.runAnalysisLoop(ctx)
}

func (m *BroadcastMonitor) listenUDPPort(ctx context.Context, port int) {
	addr := &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: port,
	}

	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		// Port might be in use by OS services (e.g. mDNS/SSDP), which is fine
		return
	}
	defer conn.Close()

	buf := make([]byte, 2048)
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

		if n > 0 && from != nil && from.IP != nil {
			srcIP := from.IP.To4()
			if srcIP != nil && !srcIP.IsLoopback() && !srcIP.IsUnspecified() {
				m.RecordPacket(srcIP.String())
			}
		}
	}
}

// RecordPacket records a broadcast/multicast packet from a given source IP
func (m *BroadcastMonitor) RecordPacket(srcIP string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	m.packetTimes[srcIP] = append(m.packetTimes[srcIP], now)
}

// Get1mCount returns the number of broadcast packets in the last 1 minute for an IP
func (m *BroadcastMonitor) Get1mCount(srcIP string) int {
	m.mu.Lock()
	defer m.mu.Unlock()

	times, found := m.packetTimes[srcIP]
	if !found {
		return 0
	}

	cutoff := time.Now().Add(-1 * time.Minute)
	count := 0
	for _, t := range times {
		if t.After(cutoff) {
			count++
		}
	}
	return count
}

func (m *BroadcastMonitor) runAnalysisLoop(ctx context.Context) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			m.evaluateStats(ctx)
		}
	}
}

func (m *BroadcastMonitor) evaluateStats(ctx context.Context) {
	m.mu.Lock()
	cutoff := time.Now().Add(-1 * time.Minute)

	// Clean up expired timestamps
	counts := make(map[string]int)
	for ip, times := range m.packetTimes {
		var valid []time.Time
		for _, t := range times {
			if t.After(cutoff) {
				valid = append(valid, t)
			}
		}
		if len(valid) > 0 {
			m.packetTimes[ip] = valid
			counts[ip] = len(valid)
		} else {
			delete(m.packetTimes, ip)
		}
	}
	m.mu.Unlock()

	// Update DB and check for newly triggered storms
	for ip, count := range counts {
		isStorming := count >= StormThreshold1m

		m.mu.Lock()
		wasStorming := m.storming[ip]
		m.storming[ip] = isStorming
		m.mu.Unlock()

		_ = m.db.UpdateHostBroadcastStats(ip, count, isStorming)

		// Newly started storming -> send urgent webhook alert
		if isStorming && !wasStorming {
			log.Printf("[WARN] 🚨 Broadcast Storm detected from host %s: %d pkts/min!", ip, count)
			if host, err := m.db.GetHost(ip); err == nil && host != nil {
				_ = m.notifier.NotifyBroadcastStorm(ctx, host, count)
			}
		}
	}
}
