package scanner

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"lanmap/internal/config"
	"lanmap/internal/db"
)

// ScanReport summarizes detection of a host in a scan run
type ScanReport struct {
	Host            *db.Host
	IsNew           bool
	IsReplaced      bool
	UnapprovedAlert bool
}

// Scanner orchestrates network scanning
type Scanner struct {
	db     *db.DB
	config *config.Config
	mu     sync.Mutex
}

// NewScanner creates a new Scanner instance
func NewScanner(database *db.DB, cfg *config.Config) *Scanner {
	return &Scanner{
		db:     database,
		config: cfg,
	}
}

// ScanAll scans all enabled segments sequentially to protect bandwidth (2.3)
func (s *Scanner) ScanAll(ctx context.Context) ([]*ScanReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	segments, err := s.db.ListSegments()
	if err != nil {
		return nil, fmt.Errorf("failed to list segments: %w", err)
	}

	var allReports []*ScanReport
	for _, seg := range segments {
		if !seg.IsEnabled || seg.CIDR == "" {
			continue
		}
		select {
		case <-ctx.Done():
			return allReports, ctx.Err()
		default:
		}

		reports, err := s.scanSegmentInternal(ctx, seg)
		if err != nil {
			log.Printf("[WARN] Scanner: error scanning segment %s (%s): %v", seg.Name, seg.CIDR, err)
			continue
		}
		allReports = append(allReports, reports...)
	}

	return allReports, nil
}

// ScanSegment scans a single segment
func (s *Scanner) ScanSegment(ctx context.Context, seg *db.Segment) ([]*ScanReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.scanSegmentInternal(ctx, seg)
}

func (s *Scanner) scanSegmentInternal(ctx context.Context, seg *db.Segment) ([]*ScanReport, error) {
	ips, err := generateIPs(seg.CIDR)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CIDR %s: %w", seg.CIDR, err)
	}

	concurrency := s.config.ScanConcurrency
	if concurrency <= 0 {
		concurrency = 20
	}

	type pingTaskResult struct {
		ip     net.IP
		result PingResult
	}

	taskChan := make(chan net.IP, len(ips))
	for _, ip := range ips {
		taskChan <- ip
	}
	close(taskChan)

	resChan := make(chan pingTaskResult, len(ips))
	var wg sync.WaitGroup

	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range taskChan {
				select {
				case <-ctx.Done():
					return
				default:
				}
				res := Ping(ip, 800*time.Millisecond)
				resChan <- pingTaskResult{ip: ip, result: res}
			}
		}()
	}

	wg.Wait()
	close(resChan)

	respondedIPs := make(map[string]bool)
	var reports []*ScanReport

	for r := range resChan {
		if !r.result.Alive {
			continue
		}

		ipStr := r.ip.String()
		respondedIPs[ipStr] = true

		mac := ResolveMAC(ipStr)
		vendor := ""
		if mac != "" {
			vendor = LookupVendor(mac)
		}
		hostname := ResolveHostname(ipStr, 500*time.Millisecond)
		osVendor := DetectOSByTTL(r.result.TTL)

		hostObj := &db.Host{
			IP:          ipStr,
			SegmentID:   &seg.ID,
			MACAddress:  mac,
			Hostname:    hostname,
			VendorModel: vendor,
			OSVendor:    osVendor,
			Status:      "up",
		}

		isNew, isReplaced, err := s.db.UpsertHostOnScan(hostObj)
		if err != nil {
			log.Printf("[ERROR] Scanner: failed to upsert host %s: %v", ipStr, err)
			continue
		}

		savedHost, err := s.db.GetHost(ipStr)
		if err != nil || savedHost == nil {
			savedHost = hostObj
		}

		unapproved := !savedHost.IsApproved
		reports = append(reports, &ScanReport{
			Host:            savedHost,
			IsNew:           isNew,
			IsReplaced:      isReplaced,
			UnapprovedAlert: unapproved && (isNew || isReplaced),
		})
	}

	// Update offline hosts in this segment to 'down'
	existingHosts, err := s.db.ListHosts(&seg.ID, false)
	if err == nil {
		for _, eh := range existingHosts {
			if !respondedIPs[eh.IP] && eh.Status == "up" {
				_ = s.db.UpdateHostStatus(eh.IP, "down")
			}
		}
	}

	return reports, nil
}

func generateIPs(cidr string) ([]net.IP, error) {
	ip, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}

	var ips []net.IP
	ipv4 := ip.To4()
	if ipv4 == nil {
		// IPv6 placeholder (Section 4.2.1 notes IPv4 is primarily targeted for v1.0)
		return []net.IP{ip}, nil
	}

	mask := binary.BigEndian.Uint32(ipNet.Mask)
	start := binary.BigEndian.Uint32(ipv4) & mask
	end := start | ^mask

	// Check subnet size
	total := end - start + 1
	if total <= 2 {
		// /31 or /32 point-to-point
		for i := start; i <= end; i++ {
			b := make(net.IP, 4)
			binary.BigEndian.PutUint32(b, i)
			ips = append(ips, b)
		}
		return ips, nil
	}

	// Exclude network and broadcast addresses
	for i := start + 1; i < end; i++ {
		b := make(net.IP, 4)
		binary.BigEndian.PutUint32(b, i)
		ips = append(ips, b)
	}

	return ips, nil
}
