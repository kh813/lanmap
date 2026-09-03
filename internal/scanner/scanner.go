package scanner

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
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

// EnsureLocalSegmentAutoRegistered auto-creates local LAN segment if no segment has CIDR
func (s *Scanner) EnsureLocalSegmentAutoRegistered() error {
	segments, err := s.db.ListSegments()
	if err != nil {
		return err
	}

	hasCustomCIDR := false
	for _, seg := range segments {
		if !seg.IsDefault && seg.CIDR != "" {
			hasCustomCIDR = true
			break
		}
	}

	if !hasCustomCIDR {
		networks, err := DetectLocalNetworks()
		if err == nil {
			for _, n := range networks {
				segName := fmt.Sprintf("ローカルLAN (%s)", n.Name)
				_, _ = s.db.CreateSegment(segName, n.CIDR, n.Name, true)
				log.Printf("[INFO] Auto-detected and registered local network segment: %s (%s)", segName, n.CIDR)
			}
		}
	}

	return nil
}

// ScanAll scans all enabled segments sequentially to protect bandwidth (2.3)
func (s *Scanner) ScanAll(ctx context.Context) ([]*ScanReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	_ = s.EnsureLocalSegmentAutoRegistered()

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
		concurrency = 30
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
				res := Ping(ip, 600*time.Millisecond)
				resChan <- pingTaskResult{ip: ip, result: res}
			}
		}()
	}

	wg.Wait()
	close(resChan)

	pingResults := make(map[string]PingResult)
	for r := range resChan {
		pingResults[r.ip.String()] = r.result
	}

	arpEntries := GetAllARPEntries()

	respondedIPs := make(map[string]bool)
	var reports []*ScanReport

	for _, ip := range ips {
		ipStr := ip.String()
		pingRes, pingOk := pingResults[ipStr]
		macFromARP, hasARP := arpEntries[ipStr]

		isAlive := (pingOk && pingRes.Alive) || (hasARP && macFromARP != "")
		if !isAlive {
			continue
		}

		respondedIPs[ipStr] = true

		mac := macFromARP
		if mac == "" {
			mac = ResolveMAC(ipStr)
		}

		vendor := ""
		if mac != "" {
			vendor = LookupVendor(mac)
		}
		hostname := ResolveHostname(ipStr, 400*time.Millisecond)

		ttl := 64
		var rttPtr *float64
		if pingOk && pingRes.Alive && pingRes.RTT > 0 {
			rttVal := float64(pingRes.RTT.Microseconds()) / 1000.0
			rttPtr = &rttVal
			if pingRes.TTL > 0 {
				ttl = pingRes.TTL
			}
		}
		osVendor := DetectOSByTTL(ttl)

		// Non-intrusive refined fingerprinting (OS, banner, model)
		fp := FingerprintHost(ipStr, hostname, vendor, osVendor)
		if fp.RefinedVendor != "" {
			vendor = fp.RefinedVendor
		}
		if fp.RefinedOS != "" {
			osVendor = fp.RefinedOS
		}

		// Auto-match against Whitelist Ledger (Section 8.2)
		isApproved := false
		displayName := ""
		if wlMatch, ok := s.db.MatchWhitelist(hostname, mac); ok {
			isApproved = true
			if wlMatch.DeviceName != "" {
				displayName = wlMatch.DeviceName
			} else {
				displayName = wlMatch.Hostname
			}
		}

		openPorts := ScanOpenPorts(ipStr, 50*time.Millisecond)
		if strings.Contains(vendor, "Apple") || osVendor == "macOS / iOS" {
			openPorts = strings.ReplaceAll(openPorts, "5000:AirPlay / UPnP (またはSynology)", "5000:AirPlay (macOS)")
		} else if strings.Contains(vendor, "Synology") {
			openPorts = strings.ReplaceAll(openPorts, "5000:AirPlay / UPnP (またはSynology)", "5000:Synology DSM")
		}

		// 1. Web Title
		httpTitle := ExtractWebTitle(ipStr, openPorts)

		// 2. UPnP / SSDP info
		var upnpName, upnpModel, upnpSerial string
		if upnp := FetchUPnPInfo(ipStr); upnp != nil {
			upnpName = upnp.FriendlyName
			upnpModel = upnp.ModelName
			upnpSerial = upnp.SerialNumber
			if vendor == "" && upnp.Manufacturer != "" {
				vendor = upnp.Manufacturer
			}
		}

		// 3. TLS Certificate
		var tlsSubj string
		var tlsExp *time.Time
		if tlsInfo := InspectTLSCert(ipStr); tlsInfo != nil {
			tlsSubj = tlsInfo.Subject
			tlsExp = &tlsInfo.Expiry
		}

		// 4. mDNS Model
		mdnsModel := ResolveMDNSModel("", hostname)

		// 5. Jitter
		var jitterPtr *float64
		if rttPtr != nil {
			jVal := RecordRTTAndCalculateJitter(ipStr, *rttPtr)
			jitterPtr = &jVal
		}

		hostObj := &db.Host{
			IP:           ipStr,
			SegmentID:    &seg.ID,
			MACAddress:   mac,
			Hostname:     hostname,
			DisplayName:  displayName,
			VendorModel:  vendor,
			OSVendor:     osVendor,
			Status:       "up",
			PingRTTMs:    rttPtr,
			PingJitterMs: jitterPtr,
			OpenPorts:    openPorts,
			HTTPTitle:    httpTitle,
			UPnPName:     upnpName,
			UPnPModel:    upnpModel,
			UPnPSerial:   upnpSerial,
			TLSSubject:   tlsSubj,
			TLSExpiry:    tlsExp,
			MDNSModel:    mdnsModel,
			IsApproved:   isApproved,
		}

		isNew, isReplaced, err := s.db.UpsertHostOnScan(hostObj)
		if err != nil {
			log.Printf("[ERROR] Scanner: failed to upsert host %s: %v", ipStr, err)
			continue
		}

		// If matched whitelist on subsequent scan, ensure approved status
		if isApproved {
			_ = s.db.UpdateHostManual(ipStr, displayName, vendor, false)
			_, _ = s.db.Exec("UPDATE hosts SET is_approved = 1 WHERE ip = ?", ipStr)
		}

		_ = s.db.RecordPingHistory(ipStr, rttPtr, "up")

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
				_ = s.db.RecordPingHistory(eh.IP, nil, "down")
			}
		}
	}

	// Purge records older than 7 days
	_ = s.db.PurgeOldPingHistory(7)

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
		return []net.IP{ip}, nil
	}

	mask := binary.BigEndian.Uint32(ipNet.Mask)
	start := binary.BigEndian.Uint32(ipv4) & mask
	end := start | ^mask

	total := end - start + 1
	if total <= 2 {
		for i := start; i <= end; i++ {
			b := make(net.IP, 4)
			binary.BigEndian.PutUint32(b, i)
			ips = append(ips, b)
		}
		return ips, nil
	}

	for i := start + 1; i < end; i++ {
		b := make(net.IP, 4)
		binary.BigEndian.PutUint32(b, i)
		ips = append(ips, b)
	}

	return ips, nil
}
