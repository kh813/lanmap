package scanner

import (
	"math"
	"sync"
)

var (
	rttHistoryMu sync.Mutex
	rttHistory   = make(map[string][]float64) // IP -> last up to 6 RTT measurements
)

// RecordRTTAndCalculateJitter tracks RTT samples and computes jitter (standard deviation)
func RecordRTTAndCalculateJitter(ip string, rttMs float64) float64 {
	rttHistoryMu.Lock()
	defer rttHistoryMu.Unlock()

	samples := rttHistory[ip]
	samples = append(samples, rttMs)
	if len(samples) > 6 {
		samples = samples[len(samples)-6:]
	}
	rttHistory[ip] = samples

	if len(samples) < 2 {
		return 0.0
	}

	// Calculate standard deviation
	var sum float64
	for _, v := range samples {
		sum += v
	}
	mean := sum / float64(len(samples))

	var varianceSum float64
	for _, v := range samples {
		varianceSum += (v - mean) * (v - mean)
	}

	stddev := math.Sqrt(varianceSum / float64(len(samples)))
	return math.Round(stddev*10) / 10.0
}
