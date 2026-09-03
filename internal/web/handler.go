package web

import (
	"context"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"lanmap/internal/config"
	"lanmap/internal/db"
	"lanmap/internal/kuma"
	"lanmap/internal/notifier"
	"lanmap/internal/scanner"
	"lanmap/web"
)

// Handler holds dependencies for web request handling
type Handler struct {
	db       *db.DB
	cfg      *config.Config
	scanner  *scanner.Scanner
	notifier *notifier.Notifier
	kuma     *kuma.Manager
	tmpl     *template.Template
}

// NewHandler creates a new web Handler
func NewHandler(database *db.DB, cfg *config.Config, sc *scanner.Scanner, notif *notifier.Notifier, km *kuma.Manager) (*Handler, error) {
	tmpl, err := template.New("base").ParseFS(web.WebFS, "template/*.html", "template/partials/*.html")
	if err != nil {
		return nil, fmt.Errorf("failed to parse templates: %w", err)
	}

	return &Handler{
		db:       database,
		cfg:      cfg,
		scanner:  sc,
		notifier: notif,
		kuma:     km,
		tmpl:     tmpl,
	}, nil
}

// HandleIndex serves the main single-page layout
func (h *Handler) HandleIndex(w http.ResponseWriter, r *http.Request) {
	if err := h.tmpl.ExecuteTemplate(w, "index.html", nil); err != nil {
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
	kumaStatus, _ := h.kuma.GetStatus()

	var selectedID int64
	if sIDStr := r.URL.Query().Get("segment_id"); sIDStr != "" {
		selectedID, _ = strconv.ParseInt(sIDStr, 10, 64)
	}

	data := map[string]interface{}{
		"Segments":          segments,
		"SelectedSegmentID": selectedID,
		"TotalHostsCount":   len(hosts),
		"KumaStatus":        kumaStatus,
	}

	_ = h.tmpl.ExecuteTemplate(w, "sidebar.html", data)
}

// HandleMainTablePartial renders the main host table partial
func (h *Handler) HandleMainTablePartial(w http.ResponseWriter, r *http.Request) {
	var segID *int64
	var segTitle = "すべてのホスト"
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

	_ = h.tmpl.ExecuteTemplate(w, "action_menu.html", map[string]interface{}{
		"Host": host,
	})
}

// HandleConflictModal renders conflict resolution modal
func (h *Handler) HandleConflictModal(w http.ResponseWriter, r *http.Request) {
	ip := r.URL.Query().Get("ip")
	host, err := h.db.GetHost(ip)
	if err != nil || host == nil {
		http.Error(w, "Host not found", http.StatusNotFound)
		return
	}

	_ = h.tmpl.ExecuteTemplate(w, "conflict_modal.html", map[string]interface{}{
		"Host": host,
	})
}

// HandleSettingsModal renders settings modal
func (h *Handler) HandleSettingsModal(w http.ResponseWriter, r *http.Request) {
	settings, err := h.db.GetAllSettings()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	kumaStatus, _ := h.kuma.GetStatus()
	_ = h.tmpl.ExecuteTemplate(w, "settings_modal.html", map[string]interface{}{
		"Settings":   settings,
		"KumaStatus": kumaStatus,
	})
}

// HandleAddHostModal renders add host modal
func (h *Handler) HandleAddHostModal(w http.ResponseWriter, r *http.Request) {
	segments, _ := h.db.ListSegments()
	_ = h.tmpl.ExecuteTemplate(w, "add_host_modal.html", map[string]interface{}{
		"Segments": segments,
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

	_ = h.tmpl.ExecuteTemplate(w, "segment_modal.html", map[string]interface{}{
		"Segment": seg,
	})
}

// HandleWhitelistModal renders whitelist ledger management modal
func (h *Handler) HandleWhitelistModal(w http.ResponseWriter, r *http.Request) {
	entries, _ := h.db.ListWhitelistEntries()
	_ = h.tmpl.ExecuteTemplate(w, "whitelist_modal.html", map[string]interface{}{
		"Entries": entries,
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

	if host.UptimeKumaID != nil && displayName != "" && displayName != host.DisplayName {
		_ = h.kuma.EditMonitorName(r.Context(), ip, *host.UptimeKumaID, displayName)
	} else {
		_ = h.db.UpdateHostManual(ip, displayName, vendorModel, isStaticIP)
	}

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
	host, _ := h.db.GetHost(ip)
	if host != nil && host.UptimeKumaID != nil {
		_ = h.kuma.DeleteMonitor(r.Context(), ip, *host.UptimeKumaID, true)
	} else {
		_ = h.db.DeleteHost(ip)
	}

	h.HandleMainTablePartial(w, r)
}

// HandleResolveConflict resolves name conflict
func (h *Handler) HandleResolveConflict(w http.ResponseWriter, r *http.Request, ip string) {
	adopt := r.URL.Query().Get("adopt")
	err := h.kuma.ResolveConflict(r.Context(), ip, adopt == "lanmap")
	if err != nil {
		log.Printf("[ERROR] Failed to resolve conflict: %v", err)
	}
	h.HandleMainTablePartial(w, r)
}

// HandleKumaActions manages Kuma monitor actions from action menu
func (h *Handler) HandleKumaActions(w http.ResponseWriter, r *http.Request, ip string, action string) {
	host, err := h.db.GetHost(ip)
	if err != nil || host == nil {
		http.Error(w, "Host not found", http.StatusNotFound)
		return
	}

	ctx := r.Context()
	switch action {
	case "start":
		name := host.DisplayName
		if name == "" {
			name = host.Hostname
		}
		_, _ = h.kuma.AddMonitor(ctx, ip, name)
	case "pause":
		if host.UptimeKumaID != nil {
			_ = h.kuma.PauseMonitor(ctx, ip, *host.UptimeKumaID)
		}
	case "resume":
		if host.UptimeKumaID != nil {
			_ = h.kuma.ResumeMonitor(ctx, ip, *host.UptimeKumaID)
		}
	}

	h.HandleMainTablePartial(w, r)
}

// HandleCreateOrUpdateSegment creates or updates a segment
func (h *Handler) HandleCreateOrUpdateSegment(w http.ResponseWriter, r *http.Request, segID int64) {
	_ = r.ParseForm()
	name := strings.TrimSpace(r.FormValue("name"))
	cidr := strings.TrimSpace(r.FormValue("cidr"))
	iface := strings.TrimSpace(r.FormValue("interface_name"))
	isEnabled := r.FormValue("is_enabled") == "true"

	if segID > 0 {
		seg, _ := h.db.GetSegment(segID)
		if seg != nil {
			seg.Name = name
			seg.CIDR = cidr
			seg.InterfaceName = iface
			seg.IsEnabled = isEnabled
			_ = h.db.UpdateSegment(seg)
		}
	} else {
		_, _ = h.db.CreateSegment(name, cidr, iface, isEnabled)
	}

	h.HandleSidebarPartial(w, r)
}

// HandleDeleteSegment deletes a segment
func (h *Handler) HandleDeleteSegment(w http.ResponseWriter, r *http.Request, segID int64) {
	err := h.db.DeleteSegment(segID)
	if err != nil {
		log.Printf("[WARN] Failed to delete segment: %v", err)
	}
	h.HandleSidebarPartial(w, r)
}

// HandleSaveSettings saves application settings
func (h *Handler) HandleSaveSettings(w http.ResponseWriter, r *http.Request) {
	_ = r.ParseForm()

	fields := []string{
		"retention_days",
		"webhook_gchat_url",
		"webhook_slack_url",
		"webhook_teams_url",
		"webhook_discord_url",
		"webhook_line_token",
		"kuma_url",
		"kuma_username",
		"kuma_password",
		"tls_cert_path",
		"tls_key_path",
	}

	for _, f := range fields {
		val := strings.TrimSpace(r.FormValue(f))
		_ = h.db.SetSetting(f, val)
	}

	// Reconnect Kuma
	_ = h.kuma.Connect(r.Context())

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

// HandleKumaSync triggers Uptime Kuma synchronization
func (h *Handler) HandleKumaSync(w http.ResponseWriter, r *http.Request) {
	_ = h.kuma.Connect(r.Context())
	_, err := h.kuma.Sync(r.Context())
	if err != nil {
		log.Printf("[WARN] Kuma Sync error: %v", err)
	}
	h.HandleMainTablePartial(w, r)
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
