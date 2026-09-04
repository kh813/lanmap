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

// RenderUptimeBlocks24hSVG generates time-slotted uptime health blocks for the 24-hour period.
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

// PingStats7d contains comprehensive metrics over a 7-day period
type PingStats7d struct {
	StatsStr    string
	UptimePct   float64
	AvgRTT      float64
	MinRTT      float64
	MaxRTT      float64
	Jitter      float64
	TotalProbes int
	UpCount     int
	DownCount   int
}

// ComputePingStats7dDetails computes thorough 7-day ping metrics
func ComputePingStats7dDetails(items []PingHistoryItem) PingStats7d {
	now := time.Now().UTC()
	windowStart := now.Add(-7 * 24 * time.Hour)

	var items7d []PingHistoryItem
	for _, it := range items {
		if it.CreatedAt.After(windowStart) || it.CreatedAt.Equal(windowStart) {
			items7d = append(items7d, it)
		}
	}

	if len(items7d) == 0 {
		return PingStats7d{
			StatsStr:  "過去7日間: 計測データ収集中",
			UptimePct: 100.0,
		}
	}

	upCount := 0
	downCount := 0
	totalRTT := 0.0
	rttCount := 0
	minRTT := 999999.0
	maxRTT := 0.0
	var rttValues []float64

	for _, item := range items7d {
		if item.Status == "up" {
			upCount++
			if item.RTTMs != nil && *item.RTTMs >= 0 {
				val := *item.RTTMs
				totalRTT += val
				rttCount++
				rttValues = append(rttValues, val)
				if val < minRTT {
					minRTT = val
				}
				if val > maxRTT {
					maxRTT = val
				}
			}
		} else {
			downCount++
		}
	}

	upPct := (float64(upCount) / float64(len(items7d))) * 100.0
	if upPct > 100.0 {
		upPct = 100.0
	}

	avgRTT := 0.0
	if rttCount > 0 {
		avgRTT = totalRTT / float64(rttCount)
	}
	if minRTT > maxRTT {
		minRTT = avgRTT
	}

	// Calculate jitter (mean absolute consecutive difference)
	jitter := 0.0
	if len(rttValues) > 1 {
		var diffSum float64
		for i := 1; i < len(rttValues); i++ {
			diffSum += math.Abs(rttValues[i] - rttValues[i-1])
		}
		jitter = diffSum / float64(len(rttValues)-1)
	}

	statsStr := fmt.Sprintf("7日間平均 %.1fms (Min %.1f / Max %.1fms) · 稼働率 %.1f%%",
		avgRTT, minRTT, maxRTT, math.Round(upPct*10)/10)

	return PingStats7d{
		StatsStr:    statsStr,
		UptimePct:   math.Round(upPct*10) / 10,
		AvgRTT:      math.Round(avgRTT*10) / 10,
		MinRTT:      math.Round(minRTT*10) / 10,
		MaxRTT:      math.Round(maxRTT*10) / 10,
		Jitter:      math.Round(jitter*10) / 10,
		TotalProbes: len(items7d),
		UpCount:     upCount,
		DownCount:   downCount,
	}
}

// ComputePingStats7d computes 7-day stats summary string and uptime %
func ComputePingStats7d(items []PingHistoryItem) (statsStr string, upPct float64) {
	d := ComputePingStats7dDetails(items)
	return d.StatsStr, d.UptimePct
}

// RenderSparkline7dSVG generates a detailed 7-day time-proportional SVG chart with date axis grid
func RenderSparkline7dSVG(items []PingHistoryItem, width, height int) template.HTML {
	if width <= 0 {
		width = 920
	}
	if height <= 0 {
		height = 200
	}

	now := time.Now().UTC()
	duration := 7 * 24 * time.Hour
	windowStart := now.Add(-duration)

	var items7d []PingHistoryItem
	for _, it := range items {
		if it.CreatedAt.After(windowStart) || it.CreatedAt.Equal(windowStart) {
			items7d = append(items7d, it)
		}
	}

	padTop := 20.0
	padBottom := 28.0
	padLeft := 16.0
	padRight := 16.0
	plotWidth := float64(width) - padLeft - padRight
	plotHeight := float64(height) - padTop - padBottom
	baselineY := float64(height) - padBottom

	if len(items7d) == 0 {
		svg := fmt.Sprintf(`<svg viewBox="0 0 %d %d" class="w-full h-48 md:h-56 overflow-visible">
			<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="#94A3B8" stroke-dasharray="4,4" stroke-width="1.5" opacity="0.3" />
			<text x="%d" y="%.1f" fill="#94A3B8" font-size="12" text-anchor="middle">過去7日間: 計測データ収集中 (自動スキャン継続中)</text>
		</svg>`, width, height, padLeft, baselineY, float64(width)-padRight, baselineY, width/2, float64(height)/2.0)
		return template.HTML(svg)
	}

	// Find max and min RTT
	maxRTT := 4.0
	minRTT := 999999.0
	for _, item := range items7d {
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
	maxRTT *= 1.25
	if maxRTT < 3.0 {
		maxRTT = 3.0
	}

	// 1. Date grid lines and labels (every 24 hours = 7 days)
	var gridLines strings.Builder
	for d := 0; d <= 7; d++ {
		ratio := float64(d) / 7.0
		x := padLeft + (ratio * plotWidth)
		dayTime := windowStart.Add(time.Duration(d*24) * time.Hour).Local()
		label := dayTime.Format("01/02")
		if d == 7 {
			label = "現在"
		}

		// Vertical grid line
		gridLines.WriteString(fmt.Sprintf(`<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="#94A3B8" stroke-dasharray="2,3" stroke-width="0.8" opacity="0.25" />`,
			x, padTop, x, baselineY))
		// Date label
		gridLines.WriteString(fmt.Sprintf(`<text x="%.1f" y="%.1f" fill="#94A3B8" font-size="11" font-weight="600" text-anchor="middle" font-family="monospace">%s</text>`,
			x, baselineY+18.0, label))
	}

	// Horizontal grid lines (Max RTT and Mid RTT)
	midRTT := maxRTT / 2.0
	midY := baselineY - (0.5 * plotHeight)
	topY := baselineY - plotHeight

	gridLines.WriteString(fmt.Sprintf(`<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="#94A3B8" stroke-dasharray="2,3" stroke-width="0.8" opacity="0.2" />`,
		padLeft, midY, padLeft+plotWidth, midY))
	gridLines.WriteString(fmt.Sprintf(`<text x="%.1f" y="%.1f" fill="#94A3B8" font-size="10.5" font-weight="500" text-anchor="start" font-family="monospace" opacity="0.85">%.1fms</text>`,
		padLeft+6, midY-4, midRTT))

	gridLines.WriteString(fmt.Sprintf(`<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="#94A3B8" stroke-dasharray="2,3" stroke-width="0.8" opacity="0.2" />`,
		padLeft, topY, padLeft+plotWidth, topY))
	gridLines.WriteString(fmt.Sprintf(`<text x="%.1f" y="%.1f" fill="#94A3B8" font-size="10.5" font-weight="500" text-anchor="start" font-family="monospace" opacity="0.85">%.1fms</text>`,
		padLeft+6, topY+12, maxRTT))

	// Baseline
	gridLines.WriteString(fmt.Sprintf(`<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="#94A3B8" stroke-width="1.2" opacity="0.4" />`,
		padLeft, baselineY, padLeft+plotWidth, baselineY))

	// 2. Data points
	var points []string
	var areaPoints []string

	firstItem := items7d[0]
	firstRatio := firstItem.CreatedAt.Sub(windowStart).Seconds() / duration.Seconds()
	if firstRatio < 0 {
		firstRatio = 0
	}
	firstX := padLeft + (firstRatio * plotWidth)

	lastX := firstX
	areaPoints = append(areaPoints, fmt.Sprintf("%.1f,%.1f", firstX, baselineY))

	for _, item := range items7d {
		ratio := item.CreatedAt.Sub(windowStart).Seconds() / duration.Seconds()
		if ratio < 0 {
			ratio = 0
		}
		if ratio > 1.0 {
			ratio = 1.0
		}
		x := padLeft + (ratio * plotWidth)

		y := baselineY
		if item.Status == "up" && item.RTTMs != nil && *item.RTTMs >= 0 {
			val := *item.RTTMs
			normalized := val / maxRTT
			if normalized > 1.0 {
				normalized = 1.0
			}
			y = baselineY - (normalized * plotHeight)
		} else {
			// Down / packet loss
			y = padTop
		}

		points = append(points, fmt.Sprintf("%.1f,%.1f", x, y))
		areaPoints = append(areaPoints, fmt.Sprintf("%.1f,%.1f", x, y))
		lastX = x
	}
	areaPoints = append(areaPoints, fmt.Sprintf("%.1f,%.1f", lastX, baselineY))

	pointsStr := strings.Join(points, " ")
	areaStr := strings.Join(areaPoints, " ")

	// If data collection started recently, dashed baseline for uncollected past
	var noDataLine string
	if firstX > padLeft+6.0 {
		noDataLine = fmt.Sprintf(`<line x1="%.1f" y1="%.1f" x2="%.1f" y2="%.1f" stroke="#94A3B8" stroke-dasharray="3,3" stroke-width="1.2" opacity="0.3" />`,
			padLeft, baselineY, firstX, baselineY)
	}

	svg := fmt.Sprintf(`<svg viewBox="0 0 %d %d" class="w-full h-48 md:h-56 overflow-visible" preserveAspectRatio="none">
		<defs>
			<linearGradient id="chartGrad7d" x1="0" y1="0" x2="0" y2="1">
				<stop offset="0%%" stop-color="#3B82F6" stop-opacity="0.35" />
				<stop offset="100%%" stop-color="#3B82F6" stop-opacity="0.0" />
			</linearGradient>
		</defs>
		%s
		%s
		<polygon points="%s" fill="url(#chartGrad7d)" />
		<polyline fill="none" stroke="#3B82F6" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round" points="%s" />
	</svg>`, width, height, gridLines.String(), noDataLine, areaStr, pointsStr)

	return template.HTML(svg)
}

// RenderUptimeBlocks7dSVG generates 42 time-slotted Uptime blocks for 7 days (6 slots per day = 4 hours per slot)
func RenderUptimeBlocks7dSVG(items []PingHistoryItem, blockCount int) template.HTML {
	if blockCount <= 0 {
		blockCount = 42 // 42 blocks = 7 days * 6 slots (4h each)
	}

	now := time.Now().UTC()
	duration := 7 * 24 * time.Hour
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
		opacity := "0.2"
		title := fmt.Sprintf("%s〜%s: 未計測", bStart.Local().Format("01/02 15:04"), bEnd.Local().Format("15:04"))

		if hasData {
			opacity = "1.0"
			if hasDown && !hasUp {
				color = "#EF4444" // Red
				title = fmt.Sprintf("%s〜%s: 障害 / ダウン検知", bStart.Local().Format("01/02 15:04"), bEnd.Local().Format("15:04"))
			} else if hasDown && hasUp {
				color = "#F59E0B" // Amber
				title = fmt.Sprintf("%s〜%s: 不安定 / 一部パケットロス", bStart.Local().Format("01/02 15:04"), bEnd.Local().Format("15:04"))
			} else {
				color = "#22C55E" // Green
				title = fmt.Sprintf("%s〜%s: 正常稼働 (100%% UP)", bStart.Local().Format("01/02 15:04"), bEnd.Local().Format("15:04"))
			}
		}

		// Gap between day boundaries (every 6 blocks)
		dayGap := (i / 6) * 4
		x := i*8 + dayGap

		rects.WriteString(fmt.Sprintf(`<rect x="%d" y="0" width="6" height="18" rx="2" fill="%s" opacity="%s"><title>%s</title></rect>`,
			x, color, opacity, title))
	}

	totalWidth := (blockCount * 8) + (7 * 4)
	return template.HTML(fmt.Sprintf(`<svg viewBox="0 0 %d 18" class="w-full h-4.5">%s</svg>`, totalWidth, rects.String()))
}

