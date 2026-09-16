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
	Host               *db.Host
	IsNew              bool
	IsReplaced         bool
	UnapprovedAlert    bool
	MonitoredDownAlert bool
	MonitoredUpAlert   bool
}

// Scanner orchestrates network scanning
type Scanner struct {
	db     *db.DB
	config *config.Config
	mu     sync.Mutex
}

// NewScanner creates a new Scanner instance
func NewScanner(database *db.DB, cfg *config.Config) *Scanner {
	sc := &Scanner{
		db:     database,
		config: cfg,
	}
	if database != nil {
		SetCustomPortResolver(func(profile DeviceProfile) (map[int]string, error) {
			return database.GetActiveTargetPortsForProfile(string(profile))
		})
	}
	return sc
}

// EnsureLocalSegmentAutoRegistered discovers local network interfaces and auto-registers them.
// The interface with the default gateway route is enabled by default.
// Secondary/virtual interfaces are registered in disabled (paused) state for security.
func (s *Scanner) EnsureLocalSegmentAutoRegistered() error {
	segments, err := s.db.ListSegments()
	if err != nil {
		return err
	}

	existingCIDRs := make(map[string]bool)
	hasEnabledCustom := false
	for _, seg := range segments {
		if seg.CIDR != "" {
			existingCIDRs[seg.CIDR] = true
			if !seg.IsDefault && seg.IsEnabled {
				hasEnabledCustom = true
			}
		}
	}

	networks, err := DetectLocalNetworks()
	if err != nil {
		return err
	}

	for _, n := range networks {
		if existingCIDRs[n.CIDR] {
			continue
		}

		// Only enable if it's the default gateway interface, or if no custom segment is enabled yet
		enableScan := n.IsDefault && !hasEnabledCustom
		var segName string
		if n.IsDefault {
			segName = fmt.Sprintf("メインLAN (%s)", n.Name)
		} else {
			segName = fmt.Sprintf("ローカルLAN (%s)", n.Name)
		}

		_, err := s.db.CreateSegment(segName, n.CIDR, n.Name, enableScan)
		if err == nil {
			statusStr := "停止中 (スキャン対象外)"
			if enableScan {
				statusStr = "有効 (スキャン対象)"
				hasEnabledCustom = true
			}
			log.Printf("[INFO] Auto-detected local network %s (%s) -> 状態: %s", segName, n.CIDR, statusStr)
			existingCIDRs[n.CIDR] = true
		}
	}

	return nil
}

// ScanAll scans all enabled segments sequentially to protect bandwidth (2.3)
func (s *Scanner) ScanAll(ctx context.Context) ([]*ScanReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	_ = s.EnsureLocalSegmentAutoRegistered()

	ipv4Enabled, ipv6Enabled, _ := s.db.GetIPVersionSettings()

	segments, err := s.db.ListSegments()
	if err != nil {
		return nil, fmt.Errorf("failed to list segments: %w", err)
	}

	var allReports []*ScanReport

	if ipv4Enabled {
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
	}

	if ipv6Enabled {
		for _, seg := range segments {
			if !seg.IsEnabled {
				continue
			}
			select {
			case <-ctx.Done():
				return allReports, ctx.Err()
			default:
			}

			reports, err := ScanIPv6Segment(ctx, seg, s.db)
			if err != nil {
				log.Printf("[WARN] Scanner: IPv6 scan error on segment %s: %v", seg.Name, err)
				continue
			}
			allReports = append(allReports, reports...)
		}
	}

	// Perform daily low-noise security patrol for 1 due online host (sequential & randomized)
	s.performDailyLowNoisePatrol(ctx)

	return allReports, nil
}

// ScanSegment scans a single segment
func (s *Scanner) ScanSegment(ctx context.Context, seg *db.Segment) ([]*ScanReport, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	ipv4Enabled, ipv6Enabled, _ := s.db.GetIPVersionSettings()
	var allReports []*ScanReport

	if ipv4Enabled && seg.CIDR != "" {
		reports, err := s.scanSegmentInternal(ctx, seg)
		if err != nil {
			return nil, err
		}
		allReports = append(allReports, reports...)
	}

	if ipv6Enabled {
		reports, err := ScanIPv6Segment(ctx, seg, s.db)
		if err != nil {
			log.Printf("[WARN] Scanner: IPv6 scan error on segment %s: %v", seg.Name, err)
		} else {
			allReports = append(allReports, reports...)
		}
	}

	return allReports, nil
}

func (s *Scanner) scanSegmentInternal(ctx context.Context, seg *db.Segment) ([]*ScanReport, error) {
	ips, err := generateIPs(seg.CIDR)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CIDR %s: %w", seg.CIDR, err)
	}

	scanMode, _ := s.db.GetScanMode()

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
	localMACs := GetLocalMACAddresses()

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

		ttl := 0
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
		userName := ""
		normMAC := NormalizeMAC(mac)
		if localMACs[normMAC] {
			isApproved = true // Local machine running lanmap is inherently authorized
		} else if wlMatch, ok := s.db.MatchWhitelist(hostname, mac); ok {
			isApproved = true
			if wlMatch.DeviceName != "" {
				displayName = wlMatch.DeviceName
			} else {
				displayName = wlMatch.Hostname
			}
			if wlMatch.UserName != "" {
				userName = wlMatch.UserName
			}
		}

		var openPorts, httpTitle string
		var upnpName, upnpModel, upnpSerial string
		var tlsSubj string
		var tlsExp *time.Time
		var inferredModel string

		// Port probing based on 3-tier scanMode:
		// - "stealth": completely skip active TCP port probing
		// - "safe": probe OS-tailored key ports (ProbeHostPortsWithContext)
		// - "full": probe comprehensive 40+ common ports (ProbeHostPortsFull)
		switch scanMode {
		case db.ScanModeSafe:
			openPorts, httpTitle, upnpName, upnpModel, upnpSerial, tlsSubj, tlsExp, inferredModel = ProbeHostPortsWithContext(ipStr, vendor, osVendor, hostname, ttl)
		case db.ScanModeFull:
			openPorts, httpTitle, upnpName, upnpModel, upnpSerial, tlsSubj, tlsExp, inferredModel = ProbeHostPortsFull(ipStr, vendor, osVendor, hostname, ttl)
		case db.ScanModeStealth:
			// No active port probing in stealth mode
		}

		if inferredModel != "" {
			vendor = EnrichVendorWithModel(vendor, inferredModel)
		}

		// 4. mDNS Model & Device Info (Query target port 5353 for verified model signature)
		mdnsInfo := QueryMDNSDeviceInfoFull(ipStr, 80*time.Millisecond)

		// 4.5 NetBIOS Node Status (Query target port 137 for Windows Computer Name, Logged-in User, Workgroup, MAC)
		nbInfo := QueryNetBIOSInfo(ipStr, 80*time.Millisecond)
		if mac == "" && nbInfo.MACAddress != "" {
			mac = nbInfo.MACAddress
			if vendor == "" {
				vendor = LookupVendor(mac)
			}
		}

		// 4.6 Deep Active Probes for Full Scan Mode or hosts with matching open ports
		var smbInfo SMBDeviceInfo
		var wsdInfo *WSDDeviceInfo
		var snmpInfo *SNMPDeviceInfo

		if scanMode == db.ScanModeFull || strings.Contains(openPorts, "445") {
			smbInfo = QuerySMBDeviceInfo(ipStr, 100*time.Millisecond)
		}
		if scanMode == db.ScanModeFull || strings.Contains(openPorts, "5357") {
			wsdInfo = QueryWSDDeviceInfo(ipStr, 120*time.Millisecond)
		}
		if scanMode == db.ScanModeFull || strings.Contains(openPorts, "161") {
			snmpInfo = QuerySNMPDeviceInfo(ipStr, 100*time.Millisecond)
		}

		// 5. Deep Host Signals Synthesis (Hostname, Vendor/Model, OS & Evidence, User Hint)
		signals := SynthesizeDeepHostAttributes(
			ipStr, hostname, vendor, osVendor,
			ttl, openPorts, httpTitle, upnpName, upnpModel, inferredModel,
			mdnsInfo, nbInfo, smbInfo, wsdInfo, snmpInfo,
		)
		hostname = signals.Hostname
		refinedVendorModel := signals.VendorModel
		osVendor = signals.OSVendor
		userHint := signals.UserHint

		// 7. Jitter
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
			VendorModel:  refinedVendorModel,
			OSVendor:     osVendor,
			OSConfidence: signals.OSConfidence,
			OSEvidence:   signals.OSEvidence,
			UserName:     userName,
			UserHint:     userHint,
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
			MDNSModel:    signals.MDNSModel,
			IsApproved:   isApproved,
		}

		prevHost, _ := s.db.GetHost(ipStr)
		isMonitoredRecovery := (prevHost != nil && prevHost.IsMonitored && prevHost.Status == "down")

		isNew, isReplaced, err := s.db.UpsertHostOnScan(hostObj)
		if err != nil {
			log.Printf("[ERROR] Scanner: failed to upsert host %s: %v", ipStr, err)
			continue
		}

		// If matched whitelist on scan, ensure approved status
		if isApproved {
			_, _ = s.db.Exec("UPDATE hosts SET is_approved = 1 WHERE ip = ?", ipStr)
		}

		_ = s.db.RecordPingHistory(ipStr, rttPtr, "up")

		savedHost, err := s.db.GetHost(ipStr)
		if err != nil || savedHost == nil {
			savedHost = hostObj
		}

		unapproved := !savedHost.IsApproved
		reports = append(reports, &ScanReport{
			Host:               savedHost,
			IsNew:              isNew,
			IsReplaced:         isReplaced,
			UnapprovedAlert:    unapproved && (isNew || isReplaced),
			MonitoredUpAlert:   isMonitoredRecovery,
		})
	}

	// Update offline hosts in this segment to 'down'
	existingHosts, err := s.db.ListHosts(&seg.ID, false)
	if err == nil {
		for _, eh := range existingHosts {
			if !respondedIPs[eh.IP] && eh.Status == "up" {
				_ = s.db.UpdateHostStatus(eh.IP, "down")
				_ = s.db.RecordPingHistory(eh.IP, nil, "down")
				if eh.IsMonitored {
					reports = append(reports, &ScanReport{
						Host:               eh,
						MonitoredDownAlert: true,
					})
				}
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

// ProbeHostPortsWithContext performs active port scan and inspection with full host context (vendor, OS, hostname, TTL)
func ProbeHostPortsWithContext(ipStr, vendor, osVendor, hostname string, ttl int) (openPorts, httpTitle, upnpName, upnpModel, upnpSerial, tlsSubj string, tlsExp *time.Time, inferredModel string) {
	profile := DetermineDeviceProfile(vendor, osVendor, hostname, ttl)
	openPorts = ScanOpenPortsForProfile(ipStr, profile, 100*time.Millisecond)

	// 1. Web Title & Model
	httpTitle, inferredModel = ExtractWebTitleAndModel(ipStr, openPorts, vendor)

	// 2. UPnP / SSDP info (only probe if not a mobile client)
	if profile != ProfileAppleMobile {
		if upnp := FetchUPnPInfo(ipStr); upnp != nil {
			upnpName = upnp.FriendlyName
			upnpModel = upnp.ModelName
			upnpSerial = upnp.SerialNumber
		}
	}

	// 3. TLS Certificate (only inspect if HTTPS ports were confirmed open)
	if strings.Contains(openPorts, "443") || strings.Contains(openPorts, "8443") || strings.Contains(openPorts, "5001") {
		if tlsInfo := InspectTLSCert(ipStr); tlsInfo != nil {
			tlsSubj = tlsInfo.Subject
			tlsExp = &tlsInfo.Expiry
		}
	}

	return openPorts, httpTitle, upnpName, upnpModel, upnpSerial, tlsSubj, tlsExp, inferredModel
}

// ProbeHostPorts performs on-demand active port scan using adaptive profiling
func ProbeHostPorts(ipStr, vendor, osVendor string) (openPorts, httpTitle, upnpName, upnpModel, upnpSerial, tlsSubj string, tlsExp *time.Time, inferredModel string) {
	return ProbeHostPortsWithContext(ipStr, vendor, osVendor, "", 0)
}

// ProbeHostPortsFull performs active comprehensive port scan across 40+ common services
func ProbeHostPortsFull(ipStr, vendor, osVendor, hostname string, ttl int) (openPorts, httpTitle, upnpName, upnpModel, upnpSerial, tlsSubj string, tlsExp *time.Time, inferredModel string) {
	openPorts = ScanOpenPortsFull(ipStr, 70*time.Millisecond)

	// 1. Web Title & Model
	httpTitle, inferredModel = ExtractWebTitleAndModel(ipStr, openPorts, vendor)

	// 2. UPnP / SSDP info
	if upnp := FetchUPnPInfo(ipStr); upnp != nil {
		upnpName = upnp.FriendlyName
		upnpModel = upnp.ModelName
		upnpSerial = upnp.SerialNumber
	}

	// 3. TLS Certificate (only inspect if HTTPS ports were confirmed open)
	if strings.Contains(openPorts, "443") || strings.Contains(openPorts, "8443") || strings.Contains(openPorts, "5001") {
		if tlsInfo := InspectTLSCert(ipStr); tlsInfo != nil {
			tlsSubj = tlsInfo.Subject
			tlsExp = &tlsInfo.Expiry
		}
	}

	return openPorts, httpTitle, upnpName, upnpModel, upnpSerial, tlsSubj, tlsExp, inferredModel
}

// performDailyLowNoisePatrol sequentially inspects one due online host per scan cycle
// using low-noise adaptive scanning and randomized jitter to prevent IDS/UTM alerts.
func (s *Scanner) performDailyLowNoisePatrol(ctx context.Context) {
	scanMode, _ := s.db.GetScanMode()
	if scanMode == db.ScanModeStealth {
		// In stealth mode, do not perform active port patrol
		return
	}

	dueHost, err := s.db.GetDuePortScanHost()
	if err != nil || dueHost == nil {
		return
	}

	select {
	case <-ctx.Done():
		return
	default:
	}

	ttlVal := 0
	profile := DetermineDeviceProfile(dueHost.VendorModel, dueHost.OSVendor, dueHost.Hostname, ttlVal)
	if profile == ProfileAppleMobile {
		// Keep mobile devices in stealth, just push schedule into future
		nextScan := db.CalculateNextPortScanWithJitter(time.Now())
		_ = s.db.UpdateHostPortScanSchedule(dueHost.IP, "", nextScan)
		return
	}

	// Probe ports serially with 100ms delay between ports
	openPorts := ScanOpenPortsLowNoise(dueHost.IP, profile, 60*time.Millisecond, 100*time.Millisecond)

	nextScan := db.CalculateNextPortScanWithJitter(time.Now())
	err = s.db.UpdateHostPortScanSchedule(dueHost.IP, openPorts, nextScan)
	if err == nil {
		log.Printf("[INFO] Daily Security Patrol: checked %s (profile: %s, open ports: [%s]), next scan: %s",
			dueHost.IP, profile, openPorts, nextScan.Format("2006-01-02 15:04"))
	}
}

// DeepHostSignals holds resolved host attributes synthesized from multi-protocol probes
type DeepHostSignals struct {
	Hostname         string
	VendorModel      string
	OSVendor         string
	OSConfidence     string
	OSEvidence       string
	UserHint         string
	MDNSModel        string
	InferredWinModel string
	InferredNASModel string
	SMBComputerName  string
	SMBDNSHostName   string
	SMBOSVersion     string
	WSDModel         string
	WSDManufacturer  string
	SNMPSysName      string
}

// SynthesizeDeepHostAttributes merges all active/passive probe results into refined host metadata
func SynthesizeDeepHostAttributes(
	ipStr, currentHostname, currentVendor, currentOS string,
	ttl int, openPorts, httpTitle, upnpName, upnpModel, inferredModel string,
	mdnsInfo MDNSDeviceInfo, nbInfo NetBIOSInfo,
	smbInfo SMBDeviceInfo, wsdInfo *WSDDeviceInfo, snmpInfo *SNMPDeviceInfo,
) DeepHostSignals {
	resolvedHostname := currentHostname

	// Hostname resolution priority:
	// If currentHostname is empty or generic auto-generated ID ("DESKTOP-...", "LAPTOP-..."):
	if resolvedHostname == "" || strings.HasPrefix(strings.ToUpper(resolvedHostname), "DESKTOP-") || strings.HasPrefix(strings.ToUpper(resolvedHostname), "LAPTOP-") {
		if smbInfo.DNSHostName != "" {
			resolvedHostname = smbInfo.DNSHostName
		} else if smbInfo.ComputerName != "" {
			resolvedHostname = smbInfo.ComputerName
		} else if nbInfo.ComputerName != "" {
			resolvedHostname = nbInfo.ComputerName
		} else if wsdInfo != nil && wsdInfo.FriendlyName != "" {
			resolvedHostname = wsdInfo.FriendlyName
		} else if snmpInfo != nil && snmpInfo.SysName != "" {
			resolvedHostname = snmpInfo.SysName
		} else if mdnsInfo.DeviceName != "" {
			resolvedHostname = mdnsInfo.DeviceName
		}
	}

	// Model resolution:
	mdnsModel := mdnsInfo.Model
	winModel := ""
	if wsdInfo != nil && wsdInfo.ModelName != "" {
		winModel = wsdInfo.ModelName
		if wsdInfo.Manufacturer != "" && !strings.Contains(strings.ToLower(winModel), strings.ToLower(wsdInfo.Manufacturer)) {
			winModel = wsdInfo.Manufacturer + " " + winModel
		}
	}
	if winModel == "" && mdnsModel == "" {
		winModel = ResolveWindowsModel(upnpModel, upnpName, resolvedHostname, currentVendor)
	}

	nasModel := ""
	if mdnsModel == "" && winModel == "" {
		nasModel = ResolveNASModel(upnpModel, upnpName, httpTitle, resolvedHostname, currentVendor)
		if nasModel == "" && snmpInfo != nil && snmpInfo.SysDescr != "" {
			nasModel = ResolveNASModel(upnpModel, upnpName, snmpInfo.SysDescr, resolvedHostname, currentVendor)
		}
	}

	wsdManufacturer := ""
	wsdModelName := ""
	if wsdInfo != nil {
		wsdManufacturer = wsdInfo.Manufacturer
		wsdModelName = wsdInfo.ModelName
	}

	snmpDescr := ""
	snmpSysName := ""
	if snmpInfo != nil {
		snmpDescr = snmpInfo.SysDescr
		snmpSysName = snmpInfo.SysName
	}

	scoreRes := ScoreOS(OSScoreInput{
		IP:              ipStr,
		Hostname:        resolvedHostname,
		Vendor:          currentVendor,
		TTL:             ttl,
		MDNSModel:       mdnsModel,
		MDNSDevice:      mdnsInfo.DeviceName,
		MacOSVer:        mdnsInfo.MacOSVer,
		NetBIOSName:     nbInfo.ComputerName,
		NetBIOSUser:     nbInfo.UserName,
		NetBIOSDomain:   nbInfo.Workgroup,
		IsNetBIOS:       nbInfo.IsWindows,
		HTTPTitle:       httpTitle,
		UPnPName:        upnpName,
		UPnPModel:       upnpModel,
		OpenPorts:       openPorts,
		SMBOSVersion:    smbInfo.OSVersion,
		WSDManufacturer: wsdManufacturer,
		WSDModel:        wsdModelName,
		SNMPDescr:       snmpDescr,
		InitialOS:       currentOS,
	})

	resolvedOS := currentOS
	if scoreRes.OS != "" {
		resolvedOS = scoreRes.OS
	}

	userHint := ExtractUserHint(nbInfo.UserName, resolvedHostname, mdnsInfo.DeviceName, upnpName)
	refinedVendorModel := RefineVendorModel(currentVendor, mdnsModel, winModel, nasModel, inferredModel, resolvedOS, resolvedHostname)

	return DeepHostSignals{
		Hostname:         resolvedHostname,
		VendorModel:      refinedVendorModel,
		OSVendor:         resolvedOS,
		OSConfidence:     scoreRes.Confidence,
		OSEvidence:       scoreRes.Evidence,
		UserHint:         userHint,
		MDNSModel:        mdnsModel,
		InferredWinModel: winModel,
		InferredNASModel: nasModel,
		SMBComputerName:  smbInfo.ComputerName,
		SMBDNSHostName:   smbInfo.DNSHostName,
		SMBOSVersion:     smbInfo.OSVersion,
		WSDModel:         wsdModelName,
		WSDManufacturer:  wsdManufacturer,
		SNMPSysName:      snmpSysName,
	}
}

