package kuma

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/breml/go-uptime-kuma-client/monitor"
	"lanmap/internal/db"
)

// SyncResult summarizes sync outcomes
type SyncResult struct {
	PatternACount int // Auto connected
	PatternBCount int // Conflict detected
	PatternCCount int // Auto imported
	PatternDCount int // Unlinked
}

// Sync performs bidirectional synchronization and reconciliation according to section 9.1
func (m *Manager) Sync(ctx context.Context) (*SyncResult, error) {
	m.mu.Lock()
	api := m.api
	m.mu.Unlock()

	if api == nil {
		return nil, fmt.Errorf("kuma is not connected")
	}

	monitors, err := api.GetMonitors(ctx)
	if err != nil {
		m.mu.Lock()
		m.status = "🔴 同期エラー"
		m.lastError = err.Error()
		m.mu.Unlock()
		return nil, fmt.Errorf("failed to get monitors: %w", err)
	}

	// Map IP -> Monitor details
	type monInfo struct {
		ID       int64
		Name     string
		IsActive bool
		Hostname string
	}
	kumaByIP := make(map[string]monInfo)
	kumaByID := make(map[int64]monInfo)

	for _, b := range monitors {
		var hostname string
		var pingMon monitor.Ping
		if err := api.GetMonitorAs(ctx, b.ID, &pingMon); err == nil && pingMon.Hostname != "" {
			hostname = pingMon.Hostname
		} else {
			var httpMon monitor.HTTP
			if err := api.GetMonitorAs(ctx, b.ID, &httpMon); err == nil && httpMon.URL != "" {
				hostname = extractHostFromURL(httpMon.URL)
			}
		}

		if hostname != "" {
			ip := extractIP(hostname)
			if ip != "" {
				info := monInfo{
					ID:       b.ID,
					Name:     b.Name,
					IsActive: b.IsActive,
					Hostname: hostname,
				}
				kumaByIP[ip] = info
				kumaByID[b.ID] = info
			}
		}
	}

	result := &SyncResult{}
	hosts, err := m.db.ListHosts(nil, false)
	if err != nil {
		return nil, fmt.Errorf("failed to list hosts: %w", err)
	}

	lanmapHostsByIP := make(map[string]*db.Host)
	for _, h := range hosts {
		lanmapHostsByIP[h.IP] = h
	}

	// Process existing lanmap hosts
	for _, h := range hosts {
		kumaMon, found := kumaByIP[h.IP]

		if found {
			dispName := h.DisplayName
			if dispName == "" {
				dispName = h.Hostname
			}

			if dispName == kumaMon.Name || h.DisplayName == "" {
				// Pattern A: Match (or lanmap has no display name yet)
				newDisp := h.DisplayName
				if newDisp == "" {
					newDisp = kumaMon.Name
				}
				if err := m.db.UpdateHostKumaStatus(h.IP, &kumaMon.ID, true, !kumaMon.IsActive, false, kumaMon.Name); err != nil {
					log.Printf("[ERROR] Kuma sync: failed to update host %s: %v", h.IP, err)
				}
				if h.DisplayName == "" {
					_ = m.db.UpdateHostManual(h.IP, newDisp, h.VendorModel, h.IsStaticIP)
				}
				result.PatternACount++
			} else {
				// Pattern B: Display Name Conflict
				if err := m.db.UpdateHostKumaStatus(h.IP, &kumaMon.ID, true, !kumaMon.IsActive, true, kumaMon.Name); err != nil {
					log.Printf("[ERROR] Kuma sync: failed to update conflict for %s: %v", h.IP, err)
				}
				result.PatternBCount++
			}
		} else {
			// Check if host previously had a kuma ID, but it no longer exists (Pattern D)
			if h.UptimeKumaID != nil {
				if _, exists := kumaByID[*h.UptimeKumaID]; !exists {
					if err := m.db.UpdateHostKumaStatus(h.IP, nil, false, false, false, ""); err != nil {
						log.Printf("[ERROR] Kuma sync: failed to unlink deleted kuma monitor for %s: %v", h.IP, err)
					}
					result.PatternDCount++
				}
			}
		}
	}

	// Process Pattern C: Monitors in Kuma that do not exist in lanmap
	defSeg, err := m.db.GetDefaultSegment()
	var defSegID *int64
	if defSeg != nil {
		defSegID = &defSeg.ID
	}

	for ip, km := range kumaByIP {
		if _, exists := lanmapHostsByIP[ip]; !exists {
			// Auto import into "未分類" segment
			newHost := &db.Host{
				IP:           ip,
				SegmentID:    defSegID,
				DisplayName:  km.Name,
				Hostname:     km.Hostname,
				Status:       "up",
				IsApproved:   false,
				IsMonitored:  true,
				IsPaused:     !km.IsActive,
				HasConflict:  false,
				KumaName:     km.Name,
				UptimeKumaID: &km.ID,
			}
			if err := m.db.CreateManualHost(newHost); err != nil {
				log.Printf("[ERROR] Kuma sync: failed to auto-import host %s: %v", ip, err)
			} else {
				result.PatternCCount++
			}
		}
	}

	return result, nil
}

// AddMonitor creates a new Ping monitor in Uptime Kuma for a host
func (m *Manager) AddMonitor(ctx context.Context, ip, displayName string) (int64, error) {
	m.mu.Lock()
	api := m.api
	m.mu.Unlock()

	if api == nil {
		return 0, fmt.Errorf("kuma is not connected")
	}

	if displayName == "" {
		displayName = ip
	}

	pingMon := &monitor.Ping{
		Base: monitor.Base{
			Name:     displayName,
			Interval: 60,
			IsActive: true,
		},
		PingDetails: monitor.PingDetails{
			Hostname: ip,
		},
	}

	id, err := api.CreateMonitor(ctx, pingMon)
	if err != nil {
		return 0, fmt.Errorf("failed to create kuma monitor: %w", err)
	}

	_ = m.db.UpdateHostKumaStatus(ip, &id, true, false, false, displayName)
	return id, nil
}

// PauseMonitor pauses monitoring in Uptime Kuma
func (m *Manager) PauseMonitor(ctx context.Context, ip string, kumaID int64) error {
	m.mu.Lock()
	api := m.api
	m.mu.Unlock()

	if api == nil {
		return fmt.Errorf("kuma is not connected")
	}

	if err := api.PauseMonitor(ctx, kumaID); err != nil {
		return err
	}

	return m.db.UpdateHostKumaStatus(ip, &kumaID, true, true, false, "")
}

// ResumeMonitor resumes monitoring in Uptime Kuma
func (m *Manager) ResumeMonitor(ctx context.Context, ip string, kumaID int64) error {
	m.mu.Lock()
	api := m.api
	m.mu.Unlock()

	if api == nil {
		return fmt.Errorf("kuma is not connected")
	}

	if err := api.ResumeMonitor(ctx, kumaID); err != nil {
		return err
	}

	return m.db.UpdateHostKumaStatus(ip, &kumaID, true, false, false, "")
}

// EditMonitorName updates the monitor name in Uptime Kuma
func (m *Manager) EditMonitorName(ctx context.Context, ip string, kumaID int64, newName string) error {
	m.mu.Lock()
	api := m.api
	m.mu.Unlock()

	if api != nil {
		var pingMon monitor.Ping
		if err := api.GetMonitorAs(ctx, kumaID, &pingMon); err == nil {
			pingMon.Name = newName
			_ = api.UpdateMonitor(ctx, &pingMon)
		}
	}

	h, err := m.db.GetHost(ip)
	if err != nil || h == nil {
		return err
	}

	_ = m.db.UpdateHostManual(ip, newName, h.VendorModel, h.IsStaticIP)
	return m.db.UpdateHostKumaStatus(ip, &kumaID, h.IsMonitored, h.IsPaused, false, newName)
}

// DeleteMonitor deletes monitor in Uptime Kuma and unlinks in lanmap
func (m *Manager) DeleteMonitor(ctx context.Context, ip string, kumaID int64, deleteHostFromDB bool) error {
	m.mu.Lock()
	api := m.api
	m.mu.Unlock()

	if api != nil {
		_ = api.DeleteMonitor(ctx, kumaID)
	}

	if deleteHostFromDB {
		return m.db.DeleteHost(ip)
	}

	return m.db.UpdateHostKumaStatus(ip, nil, false, false, false, "")
}

// ResolveConflict adopts either lanmap display name or Kuma name
func (m *Manager) ResolveConflict(ctx context.Context, ip string, adoptLanmapName bool) error {
	h, err := m.db.GetHost(ip)
	if err != nil || h == nil {
		return fmt.Errorf("host not found: %s", ip)
	}

	if h.UptimeKumaID == nil {
		return fmt.Errorf("host has no kuma id")
	}

	if adoptLanmapName {
		return m.EditMonitorName(ctx, ip, *h.UptimeKumaID, h.DisplayName)
	}

	// Adopt Kuma Name
	_ = m.db.UpdateHostManual(ip, h.KumaName, h.VendorModel, h.IsStaticIP)
	return m.db.UpdateHostKumaStatus(ip, h.UptimeKumaID, h.IsMonitored, h.IsPaused, false, h.KumaName)
}

func extractHostFromURL(rawURL string) string {
	rawURL = strings.TrimSpace(rawURL)
	if !strings.HasPrefix(rawURL, "http://") && !strings.HasPrefix(rawURL, "https://") {
		rawURL = "http://" + rawURL
	}
	parts := strings.Split(rawURL, "/")
	if len(parts) >= 3 {
		hostPort := parts[2]
		host, _, err := net.SplitHostPort(hostPort)
		if err == nil {
			return host
		}
		return hostPort
	}
	return ""
}

func extractIP(host string) string {
	host = strings.TrimSpace(host)
	ip := net.ParseIP(host)
	if ip != nil {
		return ip.String()
	}
	return ""
}
