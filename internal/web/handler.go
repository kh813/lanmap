package web

import (
	"context"
	"fmt"
	"html"
	"html/template"
	"io/fs"
	"log"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"lanmap/internal/config"
	"lanmap/internal/db"
	"lanmap/internal/i18n"
	"lanmap/internal/notifier"
	"lanmap/internal/scanner"
	"lanmap/internal/updater"
	"lanmap/web"
)

// Handler holds dependencies for web request handling
type Handler struct {
	db       *db.DB
	cfg      *config.Config
	scanner  *scanner.Scanner
	notifier *notifier.Notifier
	tmpl     *template.Template
}

// NewHandler creates a new web Handler
func NewHandler(database *db.DB, cfg *config.Config, sc *scanner.Scanner, notif *notifier.Notifier) (*Handler, error) {
	tmpl, err := template.New("base").Funcs(template.FuncMap{
		"t":        i18n.T,
		"tf":       i18n.TF,
		"safeHTML": func(s string) template.HTML { return template.HTML(s) },
	}).ParseFS(web.WebFS, "template/*.html", "template/partials/*.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse templates: %w", err)
	}

	return &Handler{
		db:       database,
		cfg:      cfg,
		scanner:  sc,
		notifier: notif,
		tmpl:     tmpl,
	}, nil
}

// HandleIndex serves the main single-page layout
func (h *Handler) HandleIndex(w http.ResponseWriter, r *http.Request) {
	lang := i18n.DetectLanguage(r)
	if err := h.tmpl.ExecuteTemplate(w, "index.html", map[string]interface{}{
		"Lang":    lang,
		"Version": h.cfg.Version,
	}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// HandleSidebarPartial renders the sidebar partial
func (h *Handler) HandleSidebarPartial(w http.ResponseWriter, r *http.Request) {
	segments, err := h.db.ListSegments()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	hosts, _ := h.db.ListHosts(nil, false)

	var selectedID int64
	if sIDStr := r.URL.Query().Get("segment_id"); sIDStr != "" {
		selectedID, _ = strconv.ParseInt(sIDStr, 10, 64)
	}

	unadded := h.getUnaddedLocalNetworks()

	data := map[string]interface{}{
		"Segments":          segments,
		"SelectedSegmentID": selectedID,
		"TotalHostsCount":   len(hosts),
		"UnaddedCount":      len(unadded),
		"Version":           h.cfg.Version,
		"Lang":              i18n.DetectLanguage(r),
	}

	_ = h.tmpl.ExecuteTemplate(w, "sidebar.html", data)
}

// getUnaddedLocalNetworks returns active local network interfaces not currently registered in DB
func (h *Handler) getUnaddedLocalNetworks() []scanner.DetectedNetwork {
	segments, err := h.db.ListSegments()
	if err != nil {
		return nil
	}

	existingCIDRs := make(map[string]bool)
	for _, seg := range segments {
		if seg.CIDR != "" {
			existingCIDRs[seg.CIDR] = true
		}
	}

	networks, err := scanner.DetectLocalNetworks()
	if err != nil {
		return nil
	}

	var unadded []scanner.DetectedNetwork
	for _, n := range networks {
		if !existingCIDRs[n.CIDR] {
			unadded = append(unadded, n)
		}
	}
	return unadded
}

// HandleMainTablePartial renders the main host table partial
func (h *Handler) HandleMainTablePartial(w http.ResponseWriter, r *http.Request) {
	lang := i18n.DetectLanguage(r)
	var segID *int64
	var segTitle = i18n.T(lang, "sidebar_all_hosts")
	var segCIDR = ""

	sIDStr := r.URL.Query().Get("segment_id")
	if sIDStr != "" {
		if id, err := strconv.ParseInt(sIDStr, 10, 64); err == nil && id > 0 {
			segID = &id
			if seg, _ := h.db.GetSegment(id); seg != nil {
				segTitle = seg.Name
				segCIDR = seg.CIDR
			}
		}
	}

	onlineOnly := r.URL.Query().Get("online_only") == "true"
	hosts, err := h.db.ListHosts(segID, onlineOnly)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	allSegs, _ := h.db.ListSegments()
	segMap := make(map[int64]*db.Segment)
	for _, s := range allSegs {
		segMap[s.ID] = s
	}

	for _, host := range hosts {
		isDHCP := host.IsDHCP
		if !isDHCP {
			var targetSeg *db.Segment
			if host.SegmentID != nil {
				targetSeg = segMap[*host.SegmentID]
			}
			// Fallback: match by CIDR if segment_id is nil or segment has no DHCPRange
			if targetSeg == nil || targetSeg.DHCPRange == "" {
				hostIP := net.ParseIP(host.IP)
				if hostIP != nil {
					for _, s := range allSegs {
						if s.CIDR != "" && s.DHCPRange != "" {
							_, cidrNet, err := net.ParseCIDR(s.CIDR)
							if err == nil && cidrNet.Contains(hostIP) {
								targetSeg = s
								break
							}
						}
					}
				}
			}

			if targetSeg != nil && targetSeg.DHCPRange != "" {
				isDHCP = db.IsInDHCPRange(host.IP, targetSeg.DHCPRange)
			}
		}
		host.IsDHCP = isDHCP
	}

	var curSegIDStr string
	if segID != nil {
		curSegIDStr = strconv.FormatInt(*segID, 10)
	}

	data := map[string]interface{}{
		"Hosts":            hosts,
		"SegmentTitle":     segTitle,
		"SegmentCIDR":      segCIDR,
		"CurrentSegmentID": curSegIDStr,
		"OnlineOnly":       onlineOnly,
		"Lang":             lang,
	}

	_ = h.tmpl.ExecuteTemplate(w, "main_table.html", data)
}

// HandleActionMenuPartial renders the dropdown action menu
func (h *Handler) HandleActionMenuPartial(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	host, err := h.db.GetHost(ip)
	if err != nil || host == nil {
		http.Error(w, "Host not found", http.StatusNotFound)
		return
	}
	if !host.IsDHCP {
		seg, _ := h.db.FindSegmentForIP(net.ParseIP(host.IP))
		if seg != nil && seg.DHCPRange != "" {
			host.IsDHCP = db.IsInDHCPRange(host.IP, seg.DHCPRange)
		}
	}

	_ = h.tmpl.ExecuteTemplate(w, "action_menu.html", map[string]interface{}{
		"Host": host,
		"Lang": i18n.DetectLanguage(r),
	})
}

// HandleSettingsModal renders settings modal
func (h *Handler) HandleSettingsModal(w http.ResponseWriter, r *http.Request) {
	settings, err := h.db.GetAllSettings()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if _, ok := settings["scan_mode"]; !ok || settings["scan_mode"] == "" {
		mode, _ := h.db.GetScanMode()
		settings["scan_mode"] = mode
	}

	_ = h.tmpl.ExecuteTemplate(w, "settings_modal.html", map[string]interface{}{
		"Settings":       settings,
		"CurrentVersion": h.cfg.Version,
		"Lang":           i18n.DetectLanguage(r),
	})
}

// HandleAddHostModal renders add host modal
func (h *Handler) HandleAddHostModal(w http.ResponseWriter, r *http.Request) {
	segments, _ := h.db.ListSegments()
	_ = h.tmpl.ExecuteTemplate(w, "add_host_modal.html", map[string]interface{}{
		"Segments": segments,
		"Lang":     i18n.DetectLanguage(r),
	})
}

// HandleEditHostModal renders edit host modal
func (h *Handler) HandleEditHostModal(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	host, err := h.db.GetHost(ip)
	if err != nil || host == nil {
		http.Error(w, "Host not found", http.StatusNotFound)
		return
	}

	_ = h.tmpl.ExecuteTemplate(w, "edit_host_modal.html", map[string]interface{}{
		"Host": host,
		"Lang": i18n.DetectLanguage(r),
	})
}

// HandleHostDetailModal renders host detail modal with 7-day ping metrics & graphs
func (h *Handler) HandleHostDetailModal(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	host, err := h.db.GetHost(ip)
	if err != nil || host == nil {
		http.Error(w, "Host not found", http.StatusNotFound)
		return
	}

	// Fetch 7-day ping history
	history, _ := h.db.GetHostPingHistory(ip, 7*24*time.Hour)
	stats7d := db.ComputePingStats7dDetails(history)
	chart7dSVG := db.RenderSparkline7dSVG(history, 920, 200)
	uptimeBlocks7dSVG := db.RenderUptimeBlocks7dSVG(history, 42)

	_ = h.tmpl.ExecuteTemplate(w, "host_detail_modal.html", map[string]interface{}{
		"Host":              host,
		"History":           history,
		"Stats7d":           stats7d,
		"Chart7dSVG":        chart7dSVG,
		"UptimeBlocks7dSVG": uptimeBlocks7dSVG,
		"Lang":              i18n.DetectLanguage(r),
	})
}

// HandleHostPingTest sends an immediate on-demand ping probe and returns the result HTML
func (h *Handler) HandleHostPingTest(w http.ResponseWriter, r *http.Request, ip string) {
	if ip == "" {
		http.Error(w, "IP required", http.StatusBadRequest)
		return
	}

	targetIP := net.ParseIP(ip)
	if targetIP == nil {
		http.Error(w, "Invalid IP address", http.StatusBadRequest)
		return
	}

	res := scanner.Ping(targetIP, 1200*time.Millisecond)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if !res.Alive {
		_ = h.db.RecordPingHistory(ip, nil, "down")
		_, _ = w.Write([]byte(`
			<div class="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-red-50 dark:bg-red-950/60 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-300 font-mono text-xs font-semibold animate-fade-in">
				<span>❌</span>
				<span>応答なし (タイムアウト / 不到達)</span>
			</div>
		`))
		return
	}

	rttVal := float64(res.RTT.Microseconds()) / 1000.0
	_ = h.db.RecordPingHistory(ip, &rttVal, "up")

	ttlText := ""
	if res.TTL > 0 {
		ttlText = fmt.Sprintf(" · TTL: %d", res.TTL)
	}

	_, _ = w.Write([]byte(fmt.Sprintf(`
		<div class="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-200 dark:border-emerald-800 text-emerald-800 dark:text-emerald-200 font-mono text-xs font-bold animate-fade-in shadow-sm">
			<span>⚡</span>
			<span>疎通成功: %.1fms%s</span>
		</div>
	`, rttVal, ttlText)))
}

// HandleHostProbePorts runs an on-demand port scan and extended probe on a single host
func (h *Handler) HandleHostProbePorts(w http.ResponseWriter, r *http.Request, ip string) {
	if ip == "" {
		http.Error(w, "IP required", http.StatusBadRequest)
		return
	}

	targetIP := net.ParseIP(ip)
	if targetIP == nil {
		http.Error(w, "Invalid IP address", http.StatusBadRequest)
		return
	}

	currentHost, _ := h.db.GetHost(ip)
	vendor := ""
	osVendor := ""
	hostname := ""
	if currentHost != nil {
		vendor = currentHost.VendorModel
		osVendor = currentHost.OSVendor
		hostname = currentHost.Hostname
	}

	openPorts, httpTitle, upnpName, upnpModel, upnpSerial, tlsSubj, tlsExp := scanner.ProbeHostPortsWithContext(ip, vendor, osVendor, hostname, 0)

	_ = h.db.UpdateHostExtendedProbes(ip, openPorts, httpTitle, upnpName, upnpModel, upnpSerial, tlsSubj, tlsExp)

	lang := i18n.DetectLanguage(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("HX-Trigger", "refreshMainTable")

	updatedHost, _ := h.db.GetHost(ip)
	if updatedHost == nil {
		updatedHost = &db.Host{IP: ip, OpenPorts: openPorts, HTTPTitle: httpTitle}
	}

	_ = h.tmpl.ExecuteTemplate(w, "ports_container", map[string]interface{}{
		"Host": updatedHost,
		"Lang": lang,
	})
}

// HandleHostFullScan runs an exhaustive full port scan and extended probe on a single host
func (h *Handler) HandleHostFullScan(w http.ResponseWriter, r *http.Request, ip string) {
	if ip == "" {
		http.Error(w, "IP required", http.StatusBadRequest)
		return
	}

	targetIP := net.ParseIP(ip)
	if targetIP == nil {
		http.Error(w, "Invalid IP address", http.StatusBadRequest)
		return
	}

	currentHost, _ := h.db.GetHost(ip)
	vendor := ""
	osVendor := ""
	hostname := ""
	if currentHost != nil {
		vendor = currentHost.VendorModel
		osVendor = currentHost.OSVendor
		hostname = currentHost.Hostname
	}

	openPorts, httpTitle, upnpName, upnpModel, upnpSerial, tlsSubj, tlsExp := scanner.ProbeHostPortsFull(ip, vendor, osVendor, hostname, 0)

	_ = h.db.UpdateHostExtendedProbes(ip, openPorts, httpTitle, upnpName, upnpModel, upnpSerial, tlsSubj, tlsExp)
	now := time.Now()
	nextScan := db.CalculateNextPortScanWithJitter(now)
	_ = h.db.UpdateHostPortScanSchedule(ip, openPorts, nextScan)

	lang := i18n.DetectLanguage(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("HX-Trigger", "refreshMainTable")

	updatedHost, _ := h.db.GetHost(ip)
	if updatedHost == nil {
		updatedHost = &db.Host{IP: ip, OpenPorts: openPorts, HTTPTitle: httpTitle}
	}

	// If invoked from action menu targeting main-content, render updated main table
	if r.Header.Get("HX-Target") == "main-content" {
		h.HandleMainTablePartial(w, r)
		return
	}

	// Default: return updated ports container for the detail modal
	_ = h.tmpl.ExecuteTemplate(w, "ports_container", map[string]interface{}{
		"Host": updatedHost,
		"Lang": lang,
	})
}


// HandleSegmentModal renders segment add/edit modal
func (h *Handler) HandleSegmentModal(w http.ResponseWriter, r *http.Request) {
	var seg *db.Segment
	idStr := r.URL.Query().Get("id")
	if idStr != "" {
		if id, err := strconv.ParseInt(idStr, 10, 64); err == nil {
			seg, _ = h.db.GetSegment(id)
		}
	}
	if seg == nil {
		seg = &db.Segment{IsEnabled: true}
	}
	var unadded []scanner.DetectedNetwork
	var suggestedDHCP string
	if seg.ID == 0 {
		unadded = h.getUnaddedLocalNetworks()
		allHosts, _ := h.db.ListHosts(nil, false)
		suggestedDHCP = db.GuessDHCPRange(allHosts, "")
	} else {
		hosts, _ := h.db.ListHosts(&seg.ID, false)
		suggestedDHCP = db.GuessDHCPRange(hosts, seg.CIDR)
	}

	_ = h.tmpl.ExecuteTemplate(w, "segment_modal.html", map[string]interface{}{
		"Segment":         seg,
		"UnaddedNetworks": unadded,
		"SuggestedDHCP":   suggestedDHCP,
		"Lang":            i18n.DetectLanguage(r),
	})
}

// HandleWhitelistModal renders whitelist ledger management modal
func (h *Handler) HandleWhitelistModal(w http.ResponseWriter, r *http.Request) {
	entries, _ := h.db.ListWhitelistEntries()
	_ = h.tmpl.ExecuteTemplate(w, "whitelist_modal.html", map[string]interface{}{
		"Entries": entries,
		"Lang":    i18n.DetectLanguage(r),
	})
}

// HandleImportWhitelist imports CSV into whitelist table and auto-reconciles existing hosts
func (h *Handler) HandleImportWhitelist(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	csvData := r.FormValue("csv_data")
	if strings.TrimSpace(csvData) != "" {
		_, _ = h.db.ImportWhitelistCSV(csvData)
		_, _ = h.db.ReconcileHostsWithWhitelist()
	}
	h.HandleMainTablePartial(w, r)
}

// HandleDeleteWhitelistEntry deletes a whitelist entry
func (h *Handler) HandleDeleteWhitelistEntry(w http.ResponseWriter, r *http.Request, id int64) {
	_ = h.db.DeleteWhitelistEntry(id)
	h.HandleWhitelistModal(w, r)
}

// HandleClearWhitelist clears all whitelist entries
func (h *Handler) HandleClearWhitelist(w http.ResponseWriter, r *http.Request) {
	_ = h.db.ClearWhitelistEntries()
	h.HandleMainTablePartial(w, r)
}

// HandleToggleApproval toggles approval status
func (h *Handler) HandleToggleApproval(w http.ResponseWriter, r *http.Request, ip string) {
	_, err := h.db.ToggleApproval(ip)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.HandleMainTablePartial(w, r)
}

// HandleToggleProtection toggles protection status
func (h *Handler) HandleToggleProtection(w http.ResponseWriter, r *http.Request, ip string) {
	_, err := h.db.ToggleProtection(ip)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	h.HandleMainTablePartial(w, r)
}

// HandleToggleHostDHCP toggles the is_dhcp status of a host and auto-adjusts segment DHCP range
func (h *Handler) HandleToggleHostDHCP(w http.ResponseWriter, r *http.Request, ip string) {
	newDHCPStatus, err := h.db.ToggleHostDHCP(ip)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Auto-adjust segment DHCP range if marked as DHCP
	if newDHCPStatus {
		host, _ := h.db.GetHost(ip)
		var segID int64
		if host != nil && host.SegmentID != nil {
			segID = *host.SegmentID
		} else {
			seg, _ := h.db.FindSegmentForIP(net.ParseIP(ip))
			if seg != nil {
				segID = seg.ID
			}
		}
		if segID > 0 {
			_, _ = h.db.AutoAdjustSegmentDHCPRange(segID)
		}
	}

	w.Header().Set("HX-Trigger", "refreshMainTable, refreshSidebar")
	h.HandleMainTablePartial(w, r)
}

// HandleToggleStaticIP toggles static IP status
func (h *Handler) HandleToggleStaticIP(w http.ResponseWriter, r *http.Request, ip string) {
	host, err := h.db.GetHost(ip)
	if err != nil || host == nil {
		http.Error(w, "Host not found", http.StatusNotFound)
		return
	}
	_ = h.db.UpdateHostManual(ip, host.DisplayName, host.VendorModel, !host.IsStaticIP)
	w.WriteHeader(http.StatusOK)
}

// HandleUpdateHost updates host manual fields
func (h *Handler) HandleUpdateHost(w http.ResponseWriter, r *http.Request, ip string) {
	_ = r.ParseForm()
	displayName := r.FormValue("display_name")
	vendorModel := r.FormValue("vendor_model")
	isStaticIP := r.FormValue("is_static_ip") == "true"

	host, err := h.db.GetHost(ip)
	if err != nil || host == nil {
		http.Error(w, "Host not found", http.StatusNotFound)
		return
	}

	_ = h.db.UpdateHostManual(ip, displayName, vendorModel, isStaticIP)
	h.HandleMainTablePartial(w, r)
}

// HandleCreateHost manually creates a host
func (h *Handler) HandleCreateHost(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()
	ip := strings.TrimSpace(r.FormValue("ip"))
	if ip == "" {
		http.Error(w, "IP is required", http.StatusBadRequest)
		return
	}

	var segID *int64
	if sIDStr := r.FormValue("segment_id"); sIDStr != "" {
		if id, err := strconv.ParseInt(sIDStr, 10, 64); err == nil && id > 0 {
			segID = &id
		}
	}

	host := &db.Host{
		IP:          ip,
		SegmentID:   segID,
		DisplayName: strings.TrimSpace(r.FormValue("display_name")),
		VendorModel: strings.TrimSpace(r.FormValue("vendor_model")),
		IsApproved:  r.FormValue("is_approved") == "true",
		IsStaticIP:  r.FormValue("is_static_ip") == "true",
		Status:      "up",
	}

	if err := h.db.CreateManualHost(host); err != nil {
		log.Printf("[ERROR] Failed to manually create host: %v", err)
	}

	h.HandleMainTablePartial(w, r)
}

// HandleDeleteHost deletes a host
func (h *Handler) HandleDeleteHost(w http.ResponseWriter, r *http.Request, ip string) {
	_ = h.db.DeleteHost(ip)
	h.HandleMainTablePartial(w, r)
}

// HandleCreateOrUpdateSegment creates or updates a segment
func (h *Handler) HandleCreateOrUpdateSegment(w http.ResponseWriter, r *http.Request, segID int64) {
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	cidr := strings.TrimSpace(r.FormValue("cidr"))
	iface := strings.TrimSpace(r.FormValue("interface_name"))
	dhcpRange := strings.TrimSpace(r.FormValue("dhcp_range"))
	isEnabled := r.FormValue("is_enabled") == "true"
	isDHCPManual := r.FormValue("is_dhcp_manual") == "true"

	// Validate DHCP Range format and subnet containment
	if err := db.ValidateDHCPRange(dhcpRange, cidr); err != nil {
		w.Header().Set("HX-Retarget", "#seg-error-container")
		w.Header().Set("HX-Reswap", "innerHTML")
		w.WriteHeader(http.StatusUnprocessableEntity)
		title := "DHCP Range Error"
		if i18n.DetectLanguage(r) == "ja" {
			title = "DHCPレンジ設定エラー"
		}
		errMsg := fmt.Sprintf(`<div class="p-3 mb-3 rounded-lg bg-red-50 dark:bg-red-950/70 border border-red-200 dark:border-red-800 text-red-700 dark:text-red-300 text-xs flex items-start space-x-2 animate-fade-in shadow-xs">
			<span class="text-base shrink-0 mt-0.5">⚠️</span>
			<div class="flex-1 leading-relaxed">
				<div class="font-bold mb-0.5">%s</div>
				<div>%s</div>
			</div>
		</div>`, html.EscapeString(title), html.EscapeString(err.Error()))
		_, _ = w.Write([]byte(errMsg))
		return
	}

	if segID > 0 {
		seg, _ := h.db.GetSegment(segID)
		if seg != nil {
			seg.Name = name
			seg.CIDR = cidr
			seg.InterfaceName = iface
			seg.IsEnabled = isEnabled
			seg.DHCPRange = dhcpRange
			seg.IsDHCPManual = isDHCPManual
			_ = h.db.UpdateSegment(seg)
		}
	} else {
		_, _ = h.db.CreateSegmentWithDHCP(name, cidr, iface, isEnabled, dhcpRange, isDHCPManual)
	}

	w.Header().Set("HX-Trigger", `{"refreshSidebar":true, "refreshMainTable":true, "closeModal":true}`)
	h.HandleSidebarPartial(w, r)
}

// HandleDeleteSegment deletes a segment
func (h *Handler) HandleDeleteSegment(w http.ResponseWriter, r *http.Request, segID int64) {
	err := h.db.DeleteSegment(segID)
	if err != nil {
		log.Printf("[WARN] Failed to delete segment: %v", err)
	}
	w.Header().Set("HX-Trigger", "refreshSidebar, refreshMainTable")
	h.HandleSidebarPartial(w, r)
}

// HandleToggleSegmentEnabled toggles segment is_enabled state
func (h *Handler) HandleToggleSegmentEnabled(w http.ResponseWriter, r *http.Request, segID int64) {
	seg, err := h.db.GetSegment(segID)
	if err != nil || seg == nil {
		http.Error(w, "Segment not found", http.StatusNotFound)
		return
	}

	seg.IsEnabled = !seg.IsEnabled
	_ = h.db.UpdateSegment(seg)

	w.Header().Set("HX-Trigger", "refreshSidebar, refreshMainTable")
	h.HandleSidebarPartial(w, r)
}

// HandleSegmentMenuPartial renders segment action dropdown menu
func (h *Handler) HandleSegmentMenuPartial(w http.ResponseWriter, r *http.Request) {
	sIDStr := r.URL.Query().Get("id")
	segID, err := strconv.ParseInt(sIDStr, 10, 64)
	if err != nil || segID <= 0 {
		http.Error(w, "Invalid segment ID", http.StatusBadRequest)
		return
	}

	seg, err := h.db.GetSegment(segID)
	if err != nil || seg == nil {
		http.Error(w, "Segment not found", http.StatusNotFound)
		return
	}

	_ = h.tmpl.ExecuteTemplate(w, "segment_menu.html", map[string]interface{}{
		"Segment": seg,
		"Lang":    i18n.DetectLanguage(r),
	})
}

// HandleSetLanguage updates the user's language preference via Cookie
func (h *Handler) HandleSetLanguage(w http.ResponseWriter, r *http.Request) {
	lang := r.URL.Query().Get("lang")
	if lang == "" {
		_ = r.ParseForm()
		lang = r.FormValue("lang")
	}
	if lang != i18n.LangJA && lang != i18n.LangEN {
		lang = i18n.LangEN
	}

	http.SetCookie(w, &http.Cookie{
		Name:     i18n.CookieName,
		Value:    lang,
		Path:     "/",
		MaxAge:   365 * 24 * 3600,
		HttpOnly: false,
		SameSite: http.SameSiteLaxMode,
	})

	w.Header().Set("HX-Refresh", "true")
	w.WriteHeader(http.StatusOK)
}

// HandleSaveSettings saves application settings
func (h *Handler) HandleSaveSettings(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()

	fields := []string{
		"retention_days",
		"scan_mode",
		"port_scan_enabled",
		"webhook_gchat_url",
		"webhook_slack_url",
		"webhook_teams_url",
		"webhook_discord_url",
		"webhook_line_token",
		"tls_cert_path",
		"tls_key_path",
	}

	for _, f := range fields {
		val := strings.TrimSpace(r.FormValue(f))
		if val != "" || f != "scan_mode" {
			_ = h.db.SetSetting(f, val)
		}
	}

	scanModeVal := strings.TrimSpace(r.FormValue("scan_mode"))
	if scanModeVal != "" {
		_ = h.db.SetScanMode(scanModeVal)
	}

	// Trigger sidebar and main table refresh on body
	w.Header().Set("HX-Trigger", "refreshSidebar, refreshMainTable")

	// Render success response message
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write([]byte(`
		<div class="p-3 bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-300 dark:border-emerald-700 rounded-lg text-emerald-800 dark:text-emerald-300 flex items-center justify-between text-xs animate-fade-in">
			<div class="flex items-center space-x-2">
				<span class="text-base">✅</span>
				<span class="font-medium">設定を正常に保存しました。</span>
			</div>
			<button type="button" onclick="closeModal()" class="px-2.5 py-1 bg-emerald-600 hover:bg-emerald-700 text-white rounded text-[11px] font-bold">閉じる</button>
		</div>
	`))
}

// HandleTestWebhook sends a test notification to the specified webhook provider
func (h *Handler) HandleTestWebhook(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()

	provider := r.URL.Query().Get("provider")
	if provider == "" {
		provider = r.FormValue("provider")
	}

	targetURL := strings.TrimSpace(r.FormValue("webhook_" + provider + "_url"))
	if targetURL == "" {
		targetURL = strings.TrimSpace(r.FormValue("url"))
	}
	if targetURL == "" {
		// Fallback to saved setting in DB
		settings, _ := h.db.GetAllSettings()
		targetURL = strings.TrimSpace(settings["webhook_"+provider+"_url"])
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if targetURL == "" {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fmt.Sprintf(`
			<div class="mt-1 p-2 bg-amber-50 dark:bg-amber-950/40 border border-amber-300 dark:border-amber-700 rounded text-amber-800 dark:text-amber-300 text-[11px] flex items-start space-x-1.5 animate-fade-in">
				<span class="shrink-0 font-bold">⚠️ URL未入力:</span>
				<span>テスト送信する Webhook URL を入力してください。</span>
			</div>
		`)))
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()

	err := h.notifier.SendTestWebhook(ctx, provider, targetURL)
	if err != nil {
		w.WriteHeader(http.StatusOK)
		escapedErr := template.HTMLEscapeString(err.Error())
		escapedErr = strings.ReplaceAll(escapedErr, "\n", "<br>")
		_, _ = w.Write([]byte(fmt.Sprintf(`
			<div class="mt-1 p-2.5 bg-red-50 dark:bg-red-950/40 border border-red-300 dark:border-red-700 rounded text-red-800 dark:text-red-300 text-[11px] flex items-start space-x-1.5 animate-fade-in">
				<span class="shrink-0 font-bold">❌ 送信失敗:</span>
				<div class="leading-relaxed">%s</div>
			</div>
		`, escapedErr)))
		return
	}

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(`
		<div class="mt-1 p-2 bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-300 dark:border-emerald-700 rounded text-emerald-800 dark:text-emerald-300 text-[11px] flex items-center space-x-1.5 animate-fade-in">
			<span class="shrink-0 font-bold">✅ 送信成功:</span>
			<span>テスト通知が正常に送信されました (HTTP 200)</span>
		</div>
	`))
}

// HandleCheckUpdate queries GitHub Releases for updates
func (h *Handler) HandleCheckUpdate(w http.ResponseWriter, r *http.Request) {
	currentVer := h.cfg.Version
	if currentVer == "" {
		currentVer = config.AppVersion
	}
	rel, err := updater.CheckLatestRelease(currentVer)
	if err != nil {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fmt.Sprintf(`
			<div class="p-3 bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-800 rounded-lg text-red-700 dark:text-red-300 text-xs">
				❌ 更新確認に失敗しました: %s
			</div>
		`, err.Error())))
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if rel.IsNewer {
		bodyEscaped := template.HTMLEscapeString(rel.Body)
		if len(bodyEscaped) > 300 {
			bodyEscaped = bodyEscaped[:300] + "..."
		}
		_, _ = w.Write([]byte(fmt.Sprintf(`
			<div class="p-3 bg-blue-50 dark:bg-blue-950/60 border border-blue-200 dark:border-blue-800 rounded-lg text-xs space-y-2 text-slate-800 dark:text-slate-100 animate-fade-in">
				<div class="flex items-center justify-between">
					<span class="font-bold text-blue-700 dark:text-blue-300 text-sm">🚀 新バージョン %s が利用可能です！</span>
					<span class="text-[10px] text-slate-500">%s 公開</span>
				</div>
				<p class="text-[11px] text-slate-600 dark:text-slate-300 whitespace-pre-line font-mono bg-white/60 dark:bg-slate-900/60 p-2 rounded border border-slate-200/60 dark:border-slate-800/60">%s</p>
				<div class="pt-1 flex items-center space-x-2">
					<button type="button"
							hx-post="/api/system/update/apply?url=%s"
							hx-target="#update-check-result"
							hx-swap="innerHTML"
							hx-indicator="#update-spinner"
							class="px-4 py-2 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-bold transition shadow text-xs flex items-center space-x-1.5 cursor-pointer">
						<span>⚡</span>
						<span>今すぐ %s へアップデートして再起動</span>
					</button>
					<a href="https://github.com/kh813/lanmap/releases/tag/%s" target="_blank" rel="noopener noreferrer"
					   class="px-3 py-2 rounded-lg bg-slate-200 dark:bg-slate-800 hover:bg-slate-300 dark:hover:bg-slate-700 text-slate-700 dark:text-slate-300 font-medium transition text-xs flex items-center space-x-1">
						<span>🔗 リリースノート</span>
					</a>
				</div>
				<div id="update-spinner" class="htmx-indicator text-blue-600 dark:text-blue-400 text-xs pt-1 font-bold animate-pulse">
					⏳ 最新バイナリをダウンロードして更新・再起動中...
				</div>
			</div>
		`, rel.TagName, rel.PublishedAt.Format("2006-01-02 15:04"), bodyEscaped, template.URLQueryEscaper(rel.AssetURL), rel.TagName, rel.TagName)))
	} else {
		_, _ = w.Write([]byte(fmt.Sprintf(`
			<div class="p-3 bg-emerald-50 dark:bg-emerald-950/40 border border-emerald-200 dark:border-emerald-800 rounded-lg text-emerald-700 dark:text-emerald-300 text-xs flex items-center justify-between animate-fade-in">
				<span class="font-medium">✅ 現在、最新バージョン (%s) を使用しています。</span>
				<span class="text-[10px] text-emerald-600 dark:text-emerald-400 font-mono">最終確認: %s</span>
			</div>
		`, currentVer, time.Now().Format("15:04:05"))))
	}
}

// HandleApplyUpdate downloads and applies the new release
func (h *Handler) HandleApplyUpdate(w http.ResponseWriter, r *http.Request) {
	assetURL := r.URL.Query().Get("url")
	if assetURL == "" {
		http.Error(w, "Asset URL required", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := updater.DownloadAndApplyUpdate(assetURL); err != nil {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(fmt.Sprintf(`
			<div class="p-3 bg-red-50 dark:bg-red-950/40 border border-red-200 dark:border-red-800 rounded-lg text-red-700 dark:text-red-300 text-xs">
				❌ アップデート適用に失敗しました: %s
			</div>
		`, err.Error())))
		return
	}

	// Trigger self restart in background
	_ = updater.RestartSelf()

	_, _ = w.Write([]byte(`
		<div class="p-4 bg-emerald-50 dark:bg-emerald-950/60 border border-emerald-300 dark:border-emerald-700 rounded-lg text-emerald-800 dark:text-emerald-200 text-xs space-y-2 animate-pulse">
			<div class="font-bold text-sm flex items-center space-x-1.5">
				<span>🎉</span>
				<span>アップデートが正常に完了しました！</span>
			</div>
			<p>最新バイナリへ更新され、プロセスが自動再起動しています。5秒後に画面を自動再読み込みします...</p>
			<script>
				setTimeout(function() {
					window.location.reload();
				}, 4500);
			</script>
		</div>
	`))
}

// HandleScanNow triggers immediate network scan
func (h *Handler) HandleScanNow(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	sIDStr := r.URL.Query().Get("segment_id")
	var reports []*scanner.ScanReport

	if sIDStr != "" {
		if id, err := strconv.ParseInt(sIDStr, 10, 64); err == nil && id > 0 {
			if seg, _ := h.db.GetSegment(id); seg != nil {
				reports, _ = h.scanner.ScanSegment(ctx, seg)
			}
		}
	}

	if reports == nil {
		reports, _ = h.scanner.ScanAll(ctx)
	}

	var unapprovedHosts []*db.Host
	for _, rep := range reports {
		if rep.UnapprovedAlert {
			unapprovedHosts = append(unapprovedHosts, rep.Host)
		}
	}

	if len(unapprovedHosts) > 0 {
		_ = h.notifier.NotifyUnapprovedHosts(ctx, unapprovedHosts)
	}

	h.HandleMainTablePartial(w, r)
}

// StaticFS returns http.FileSystem for embedded static assets
func StaticFS() http.FileSystem {
	sub, err := fs.Sub(web.WebFS, "static")
	if err != nil {
		panic(err)
	}
	return http.FS(sub)
}
