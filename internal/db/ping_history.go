package db

import (
	"fmt"
	"html/template"
	"math"
	"strings"
	"time"
)

// PingHistoryItem represents a recorded ping probe
type PingHistoryItem struct {
	ID        int64
	HostIP    string
	RTTMs     *float64
	Status    string
	CreatedAt time.Time
}

// RecordPingHistory inserts a ping measurement into history
func (db *DB) RecordPingHistory(ip string, rtt *float64, status string) error {
	_, err := db.Exec("INSERT INTO ping_history (host_ip, rtt_ms, status, created_at) VALUES (?, ?, ?, ?)",
		ip, rtt, status, time.Now().UTC())
	return err
}

// PurgeOldPingHistory deletes records older than retentionDays (default 7 days)
func (db *DB) PurgeOldPingHistory(days int) error {
	if days <= 0 {
		days = 7
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -days)
	_, err := db.Exec("DELETE FROM ping_history WHERE created_at < ?", cutoff)
	return err
}

// GetHostPingHistory returns ping history for a specific host
func (db *DB) GetHostPingHistory(ip string, duration time.Duration) ([]PingHistoryItem, error) {
	if duration <= 0 {
		duration = 7 * 24 * time.Hour
	}
	cutoff := time.Now().UTC().Add(-duration)

	rows, err := db.Query("SELECT id, host_ip, rtt_ms, status, created_at FROM ping_history WHERE host_ip = ? AND created_at >= ? ORDER BY created_at ASC", ip, cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var items []PingHistoryItem
	for rows.Next() {
		var item PingHistoryItem
		var rtt *float64
		var createdAt time.Time
		if err := rows.Scan(&item.ID, &item.HostIP, &rtt, &item.Status, &createdAt); err != nil {
			return nil, err
		}
		item.RTTMs = rtt
		item.CreatedAt = createdAt
		items = append(items, item)
	}
	return items, rows.Err()
}

// GetBatchPingHistory7d returns 7-day ping history grouped by host IP
func (db *DB) GetBatchPingHistory7d() (map[string][]PingHistoryItem, error) {
	cutoff := time.Now().UTC().Add(-7 * 24 * time.Hour)
	rows, err := db.Query("SELECT id, host_ip, rtt_ms, status, created_at FROM ping_history WHERE created_at >= ? ORDER BY created_at ASC", cutoff)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	result := make(map[string][]PingHistoryItem)
	for rows.Next() {
		var item PingHistoryItem
		var rtt *float64
		var createdAt time.Time
		if err := rows.Scan(&item.ID, &item.HostIP, &rtt, &item.Status, &createdAt); err != nil {
			return nil, err
		}
		item.RTTMs = rtt
		item.CreatedAt = createdAt
		result[item.HostIP] = append(result[item.HostIP], item)
	}
	return result, rows.Err()
}

// RenderSparklineSVG generates a clean, responsive SVG sparkline for 7-day RTT latency
func RenderSparklineSVG(items []PingHistoryItem, width, height int) template.HTML {
	if width <= 0 {
		width = 280
	}
	if height <= 0 {
		height = 36
	}

	if len(items) == 0 {
		// Empty state: flat dashed line
		svg := fmt.Sprintf(`<svg viewBox="0 0 %d %d" class="w-full h-8 overflow-visible">
			<line x1="0" y1="%d" x2="%d" y2="%d" stroke="#94A3B8" stroke-dasharray="3,3" stroke-width="1.5" />
			<text x="%d" y="%d" fill="#94A3B8" font-size="9" text-anchor="middle">データ収集中 (7日間)</text>
		</svg>`, width, height, height/2, width, height/2, width/2, height/2+3)
		return template.HTML(svg)
	}

	// Find max RTT to scale Y
	maxRTT := 5.0
	minRTT := 999999.0
	for _, item := range items {
		if item.RTTMs != nil && *item.RTTMs > 0 {
			if *item.RTTMs > maxRTT {
				maxRTT = *item.RTTMs
			}
			if *item.RTTMs < minRTT {
				minRTT = *item.RTTMs
			}
		}
	}
	if minRTT > maxRTT {
		minRTT = 0.0
	}
	// Add 10% headroom
	maxRTT *= 1.15
	if maxRTT < 2.0 {
		maxRTT = 2.0
	}

	padTop := 4.0
	padBottom := 4.0
	plotHeight := float64(height) - padTop - padBottom

	var points []string
	var areaPoints []string
	stepX := float64(width) / float64(len(items)-1)
	if len(items) == 1 {
		stepX = float64(width)
	}

	lastX := float64(width)

	for i, item := range items {
		x := float64(i) * stepX
		if len(items) == 1 {
			x = float64(width) / 2
		}

		y := float64(height) - padBottom
		if item.Status == "up" && item.RTTMs != nil && *item.RTTMs >= 0 {
			val := *item.RTTMs
			normalized := val / maxRTT
			if normalized > 1.0 {
				normalized = 1.0
			}
			y = float64(height) - padBottom - (normalized * plotHeight)
		} else {
			// Down / packet loss: spike to top in red or zero
			y = padTop
		}

		if i == 0 {
			areaPoints = append(areaPoints, fmt.Sprintf("%.1f,%.1f", x, float64(height)-padBottom))
		}
		points = append(points, fmt.Sprintf("%.1f,%.1f", x, y))
		areaPoints = append(areaPoints, fmt.Sprintf("%.1f,%.1f", x, y))
		lastX = x
	}
	areaPoints = append(areaPoints, fmt.Sprintf("%.1f,%.1f", lastX, float64(height)-padBottom))

	pointsStr := strings.Join(points, " ")
	areaStr := strings.Join(areaPoints, " ")

	svg := fmt.Sprintf(`<svg viewBox="0 0 %d %d" class="w-full h-8 overflow-visible" preserveAspectRatio="none">
		<defs>
			<linearGradient id="chartGrad" x1="0" y1="0" x2="0" y2="1">
				<stop offset="0%%" stop-color="#3B82F6" stop-opacity="0.35" />
				<stop offset="100%%" stop-color="#3B82F6" stop-opacity="0.0" />
			</linearGradient>
		</defs>
		<polygon points="%s" fill="url(#chartGrad)" />
		<polyline fill="none" stroke="#3B82F6" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" points="%s" />
	</svg>`, width, height, areaStr, pointsStr)

	return template.HTML(svg)
}

// RenderUptimeBlocksSVG generates Uptime Kuma style health blocks for 7-day status
func RenderUptimeBlocksSVG(items []PingHistoryItem, blockCount int) template.HTML {
	if blockCount <= 0 {
		blockCount = 35
	}

	if len(items) == 0 {
		// Empty placeholders
		var rects strings.Builder
		for i := 0; i < blockCount; i++ {
			rects.WriteString(fmt.Sprintf(`<rect x="%d" y="0" width="5" height="14" rx="1.5" fill="#94A3B8" opacity="0.3" />`, i*7))
		}
		return template.HTML(fmt.Sprintf(`<svg viewBox="0 0 %d 14" class="w-full h-3.5">%s</svg>`, blockCount*7-2, rects.String()))
	}

	// Divide items into blockCount time buckets
	bucketSize := float64(len(items)) / float64(blockCount)
	var rects strings.Builder

	for i := 0; i < blockCount; i++ {
		startIdx := int(float64(i) * bucketSize)
		endIdx := int(float64(i+1) * bucketSize)
		if endIdx > len(items) {
			endIdx = len(items)
		}
		if startIdx >= len(items) {
			startIdx = len(items) - 1
		}
		if endIdx <= startIdx {
			endIdx = startIdx + 1
		}

		hasDown := false
		hasUp := false
		for k := startIdx; k < endIdx && k < len(items); k++ {
			if items[k].Status == "up" {
				hasUp = true
			} else {
				hasDown = true
			}
		}

		color := "#22C55E" // Green (100% UP)
		if hasDown && !hasUp {
			color = "#EF4444" // Red (100% Down)
		} else if hasDown && hasUp {
			color = "#F59E0B" // Amber (Degraded / Partial loss)
		}

		rects.WriteString(fmt.Sprintf(`<rect x="%d" y="0" width="5" height="14" rx="1.5" fill="%s" />`, i*7, color))
	}

	return template.HTML(fmt.Sprintf(`<svg viewBox="0 0 %d 14" class="w-full h-3.5">%s</svg>`, blockCount*7-2, rects.String()))
}

// ComputePingStats7d computes average RTT, min, max, and uptime % over the 7-day period
func ComputePingStats7d(items []PingHistoryItem) (statsStr string, upPct float64) {
	if len(items) == 0 {
		return "7日間: 計測データなし", 100.0
	}

	upCount := 0
	totalRTT := 0.0
	rttCount := 0
	minRTT := 999999.0
	maxRTT := 0.0

	for _, item := range items {
		if item.Status == "up" {
			upCount++
			if item.RTTMs != nil && *item.RTTMs >= 0 {
				val := *item.RTTMs
				totalRTT += val
				rttCount++
				if val < minRTT {
					minRTT = val
				}
				if val > maxRTT {
					maxRTT = val
				}
			}
		}
	}

	upPct = (float64(upCount) / float64(len(items))) * 100.0
	if upPct > 100.0 {
		upPct = 100.0
	}

	if rttCount == 0 {
		return fmt.Sprintf("7日間 稼働率: %.1f%%", upPct), upPct
	}

	avgRTT := totalRTT / float64(rttCount)
	if minRTT > maxRTT {
		minRTT = avgRTT
	}

	statsStr = fmt.Sprintf("7日平均 %.1fms (Min %.1f / Max %.1fms) · 稼働率 %.1f%%",
		avgRTT, minRTT, maxRTT, math.Round(upPct*10)/10)
	return statsStr, upPct
}
