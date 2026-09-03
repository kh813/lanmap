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

// RenderSparkline24hSVG generates a time-proportional SVG sparkline for the past 24 hours.
// If data was only collected recently, the left side remains empty/dashed to accurately reflect the no-data period.
func RenderSparkline24hSVG(items []PingHistoryItem, width, height int) template.HTML {
	if width <= 0 {
		width = 280
	}
	if height <= 0 {
		height = 36
	}

	now := time.Now().UTC()
	duration := 24 * time.Hour
	windowStart := now.Add(-duration)

	// Filter items in the 24-hour window
	var items24h []PingHistoryItem
	for _, it := range items {
		if it.CreatedAt.After(windowStart) || it.CreatedAt.Equal(windowStart) {
			items24h = append(items24h, it)
		}
	}

	padTop := 4.0
	padBottom := 4.0
	baselineY := float64(height) - padBottom
	plotHeight := float64(height) - padTop - padBottom

	if len(items24h) == 0 {
		// Empty state: flat dashed line
		svg := fmt.Sprintf(`<svg viewBox="0 0 %d %d" class="w-full h-8 overflow-visible">
			<line x1="0" y1="%.1f" x2="%d" y2="%.1f" stroke="#94A3B8" stroke-dasharray="3,3" stroke-width="1.2" opacity="0.4" />
			<text x="%d" y="%.1f" fill="#94A3B8" font-size="9" text-anchor="middle">過去24時間: データ収集中</text>
		</svg>`, width, height, baselineY, width, baselineY, width/2, float64(height)/2.0+3.0)
		return template.HTML(svg)
	}

	// Find max RTT to scale Y
	maxRTT := 4.0
	minRTT := 999999.0
	for _, item := range items24h {
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
	maxRTT *= 1.2
	if maxRTT < 2.0 {
		maxRTT = 2.0
	}

	var points []string
	var areaPoints []string

	firstItem := items24h[0]
	firstRatio := firstItem.CreatedAt.Sub(windowStart).Seconds() / duration.Seconds()
	if firstRatio < 0 {
		firstRatio = 0
	}
	firstX := firstRatio * float64(width)

	lastX := firstX
	areaPoints = append(areaPoints, fmt.Sprintf("%.1f,%.1f", firstX, baselineY))

	for _, item := range items24h {
		ratio := item.CreatedAt.Sub(windowStart).Seconds() / duration.Seconds()
		if ratio < 0 {
			ratio = 0
		}
		if ratio > 1.0 {
			ratio = 1.0
		}
		x := ratio * float64(width)

		y := baselineY
		if item.Status == "up" && item.RTTMs != nil && *item.RTTMs >= 0 {
			val := *item.RTTMs
			normalized := val / maxRTT
			if normalized > 1.0 {
				normalized = 1.0
			}
			y = baselineY - (normalized * plotHeight)
		} else {
			// Down / loss
			y = padTop
		}

		points = append(points, fmt.Sprintf("%.1f,%.1f", x, y))
		areaPoints = append(areaPoints, fmt.Sprintf("%.1f,%.1f", x, y))
		lastX = x
	}
	areaPoints = append(areaPoints, fmt.Sprintf("%.1f,%.1f", lastX, baselineY))

	pointsStr := strings.Join(points, " ")
	areaStr := strings.Join(areaPoints, " ")

	// If data collection started recently, show dashed baseline for the past unrecorded period
	var noDataLine string
	if firstX > 3.0 {
		noDataLine = fmt.Sprintf(`<line x1="0" y1="%.1f" x2="%.1f" y2="%.1f" stroke="#94A3B8" stroke-dasharray="3,3" stroke-width="1.2" opacity="0.35" />`,
			baselineY, firstX, baselineY)
	}

	svg := fmt.Sprintf(`<svg viewBox="0 0 %d %d" class="w-full h-8 overflow-visible" preserveAspectRatio="none">
		<defs>
			<linearGradient id="chartGrad" x1="0" y1="0" x2="0" y2="1">
				<stop offset="0%%" stop-color="#3B82F6" stop-opacity="0.35" />
				<stop offset="100%%" stop-color="#3B82F6" stop-opacity="0.0" />
			</linearGradient>
		</defs>
		%s
		<polygon points="%s" fill="url(#chartGrad)" />
		<polyline fill="none" stroke="#3B82F6" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" points="%s" />
	</svg>`, width, height, noDataLine, areaStr, pointsStr)

	return template.HTML(svg)
}

// RenderSparklineSVG is an alias for RenderSparkline24hSVG
func RenderSparklineSVG(items []PingHistoryItem, width, height int) template.HTML {
	return RenderSparkline24hSVG(items, width, height)
}

// RenderUptimeBlocks24hSVG generates time-slotted Uptime Kuma health blocks for the 24-hour period.
// Empty/unmonitored time slots appear as faded gray placeholders.
func RenderUptimeBlocks24hSVG(items []PingHistoryItem, blockCount int) template.HTML {
	if blockCount <= 0 {
		blockCount = 36 // 36 blocks = 1 block per 40 minutes for 24 hours
	}

	now := time.Now().UTC()
	duration := 24 * time.Hour
	windowStart := now.Add(-duration)
	bucketDuration := duration / time.Duration(blockCount)

	var rects strings.Builder
	for i := 0; i < blockCount; i++ {
		bStart := windowStart.Add(time.Duration(i) * bucketDuration)
		bEnd := bStart.Add(bucketDuration)

		hasData := false
		hasDown := false
		hasUp := false

		for _, item := range items {
			if (item.CreatedAt.After(bStart) || item.CreatedAt.Equal(bStart)) && item.CreatedAt.Before(bEnd) {
				hasData = true
				if item.Status == "up" {
					hasUp = true
				} else {
					hasDown = true
				}
			}
		}

		color := "#94A3B8"
		opacity := "0.25"

		if hasData {
			opacity = "1.0"
			if hasDown && !hasUp {
				color = "#EF4444" // Red (Down)
			} else if hasDown && hasUp {
				color = "#F59E0B" // Amber (Degraded / Partial loss)
			} else {
				color = "#22C55E" // Green (100% UP)
			}
		}

		rects.WriteString(fmt.Sprintf(`<rect x="%d" y="0" width="5" height="14" rx="1.5" fill="%s" opacity="%s" />`, i*7, color, opacity))
	}

	return template.HTML(fmt.Sprintf(`<svg viewBox="0 0 %d 14" class="w-full h-3.5">%s</svg>`, blockCount*7-2, rects.String()))
}

// RenderUptimeBlocksSVG is an alias for RenderUptimeBlocks24hSVG
func RenderUptimeBlocksSVG(items []PingHistoryItem, blockCount int) template.HTML {
	return RenderUptimeBlocks24hSVG(items, blockCount)
}

// ComputePingStats24h computes average RTT, min, max, and uptime % over the past 24-hour period
func ComputePingStats24h(items []PingHistoryItem) (statsStr string, upPct float64) {
	now := time.Now().UTC()
	windowStart := now.Add(-24 * time.Hour)

	var items24h []PingHistoryItem
	for _, it := range items {
		if it.CreatedAt.After(windowStart) || it.CreatedAt.Equal(windowStart) {
			items24h = append(items24h, it)
		}
	}

	if len(items24h) == 0 {
		return "過去24h: 計測データ収集中", 100.0
	}

	upCount := 0
	totalRTT := 0.0
	rttCount := 0
	minRTT := 999999.0
	maxRTT := 0.0

	for _, item := range items24h {
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

	upPct = (float64(upCount) / float64(len(items24h))) * 100.0
	if upPct > 100.0 {
		upPct = 100.0
	}

	if rttCount == 0 {
		return fmt.Sprintf("過去24h 稼働率: %.1f%%", upPct), upPct
	}

	avgRTT := totalRTT / float64(rttCount)
	if minRTT > maxRTT {
		minRTT = avgRTT
	}

	statsStr = fmt.Sprintf("24h平均 %.1fms (Min %.1f / Max %.1fms) · 稼働率 %.1f%%",
		avgRTT, minRTT, maxRTT, math.Round(upPct*10)/10)
	return statsStr, upPct
}

// ComputePingStats7d computes 7-day stats or delegates to 24h
func ComputePingStats7d(items []PingHistoryItem) (statsStr string, upPct float64) {
	return ComputePingStats24h(items)
}
