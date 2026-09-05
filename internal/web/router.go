package web

import (
	"net/http"
	"strconv"

	"lanmap/web"
)

// NewRouter registers HTTP routes and returns the http.Handler
func NewRouter(h *Handler) http.Handler {
	mux := http.NewServeMux()

	// Static Assets
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServer(StaticFS())))
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		http.ServeFileFS(w, r, web.WebFS, "static/favicon.ico")
	})

	// Main Layout
	mux.HandleFunc("GET /{$}", h.HandleIndex)

	// Partials
	mux.HandleFunc("GET /partials/sidebar", h.HandleSidebarPartial)
	mux.HandleFunc("GET /partials/main_table", h.HandleMainTablePartial)
	mux.HandleFunc("GET /partials/action_menu", h.HandleActionMenuPartial)
	mux.HandleFunc("GET /partials/segment_menu", h.HandleSegmentMenuPartial)
	mux.HandleFunc("GET /partials/custom_ports", h.HandleCustomPortsPartial)

	// Modals
	mux.HandleFunc("GET /modals/settings", h.HandleSettingsModal)
	mux.HandleFunc("GET /modals/segment", h.HandleSegmentModal)
	mux.HandleFunc("GET /modals/add_host", h.HandleAddHostModal)
	mux.HandleFunc("GET /modals/edit_host", h.HandleEditHostModal)
	mux.HandleFunc("GET /modals/host_detail", h.HandleHostDetailModal)
	mux.HandleFunc("GET /modals/whitelist", h.HandleWhitelistModal)
	mux.HandleFunc("GET /modals/custom_port", h.HandleCustomPortModal)
	mux.HandleFunc("GET /modals/custom_ports_import", h.HandleCustomPortsImportModal)
	mux.HandleFunc("GET /modals/federation", h.HandleFederationModal)

	// Federation API
	mux.HandleFunc("POST /api/federation/pair/start", h.HandleStartPairing)
	mux.HandleFunc("POST /api/federation/pair/request", h.HandleRequestPairing)
	mux.HandleFunc("GET /api/federation/pair/status", h.HandlePairingStatus)
	mux.HandleFunc("POST /api/federation/pair/approve", h.HandleApprovePairing)
	mux.HandleFunc("POST /api/federation/pair/reject", h.HandleRejectPairing)
	mux.HandleFunc("POST /api/federation/agents/{id}/revoke", h.HandleRevokeAgent)
	mux.HandleFunc("DELETE /api/federation/agents/{id}", h.HandleDeleteAgent)
	mux.HandleFunc("POST /api/federation/agents/{id}/delete", h.HandleDeleteAgent)
	mux.HandleFunc("POST /api/federation/report", h.HandleFederationReport)

	// Whitelist API
	mux.HandleFunc("POST /api/whitelist/import", h.HandleImportWhitelist)
	mux.HandleFunc("DELETE /api/whitelist", h.HandleClearWhitelist)
	mux.HandleFunc("DELETE /api/whitelist/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		h.HandleDeleteWhitelistEntry(w, r, id)
	})

	// Custom Ports API
	mux.HandleFunc("POST /api/ports", h.HandleCreateCustomPort)
	mux.HandleFunc("POST /api/ports/{id}/update", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		h.HandleUpdateCustomPort(w, r, id)
	})
	mux.HandleFunc("POST /api/ports/{id}/toggle", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		h.HandleToggleCustomPort(w, r, id)
	})
	mux.HandleFunc("DELETE /api/ports/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		h.HandleDeleteCustomPort(w, r, id)
	})
	mux.HandleFunc("POST /api/ports/reset", h.HandleResetCustomPorts)
	mux.HandleFunc("GET /api/ports/export", h.HandleExportCustomPortsCSV)
	mux.HandleFunc("POST /api/ports/import", h.HandleImportCustomPortsCSV)

	// Host API
	mux.HandleFunc("POST /api/hosts", h.HandleCreateHost)
	mux.HandleFunc("POST /api/hosts/{ip}/ping_test", func(w http.ResponseWriter, r *http.Request) {
		h.HandleHostPingTest(w, r, r.PathValue("ip"))
	})
	mux.HandleFunc("POST /api/hosts/{ip}/probe_ports", func(w http.ResponseWriter, r *http.Request) {
		h.HandleHostProbePorts(w, r, r.PathValue("ip"))
	})
	mux.HandleFunc("POST /api/hosts/{ip}/full_scan", func(w http.ResponseWriter, r *http.Request) {
		h.HandleHostFullScan(w, r, r.PathValue("ip"))
	})
	mux.HandleFunc("POST /api/hosts/{ip}/toggle_approval", func(w http.ResponseWriter, r *http.Request) {
		h.HandleToggleApproval(w, r, r.PathValue("ip"))
	})
	mux.HandleFunc("POST /api/hosts/{ip}/toggle_protection", func(w http.ResponseWriter, r *http.Request) {
		h.HandleToggleProtection(w, r, r.PathValue("ip"))
	})
	mux.HandleFunc("POST /api/hosts/{ip}/toggle_dhcp", func(w http.ResponseWriter, r *http.Request) {
		h.HandleToggleHostDHCP(w, r, r.PathValue("ip"))
	})
	mux.HandleFunc("POST /api/hosts/{ip}/toggle_static", func(w http.ResponseWriter, r *http.Request) {
		h.HandleToggleStaticIP(w, r, r.PathValue("ip"))
	})
	mux.HandleFunc("POST /api/hosts/{ip}/toggle_port_suppress", func(w http.ResponseWriter, r *http.Request) {
		h.HandleTogglePortSuppress(w, r, r.PathValue("ip"))
	})
	mux.HandleFunc("POST /api/hosts/{ip}/update", func(w http.ResponseWriter, r *http.Request) {
		h.HandleUpdateHost(w, r, r.PathValue("ip"))
	})
	mux.HandleFunc("DELETE /api/hosts/{ip}", func(w http.ResponseWriter, r *http.Request) {
		h.HandleDeleteHost(w, r, r.PathValue("ip"))
	})

	// Segment API
	mux.HandleFunc("POST /api/segments", func(w http.ResponseWriter, r *http.Request) {
		h.HandleCreateOrUpdateSegment(w, r, 0)
	})
	mux.HandleFunc("POST /api/segments/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		h.HandleCreateOrUpdateSegment(w, r, id)
	})
	mux.HandleFunc("DELETE /api/segments/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		h.HandleDeleteSegment(w, r, id)
	})
	mux.HandleFunc("POST /api/segments/{id}/toggle", func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		h.HandleToggleSegmentEnabled(w, r, id)
	})

	// Settings, Webhook Test, TLS Verify, Update, Scan & Language
	mux.HandleFunc("POST /api/settings", h.HandleSaveSettings)
	mux.HandleFunc("POST /api/tls/verify", h.HandleTLSVerify)
	mux.HandleFunc("POST /api/webhooks/test", h.HandleTestWebhook)
	mux.HandleFunc("GET /api/system/update/check", h.HandleCheckUpdate)
	mux.HandleFunc("POST /api/system/update/apply", h.HandleApplyUpdate)
	mux.HandleFunc("POST /api/scan", h.HandleScanNow)
	mux.HandleFunc("POST /api/set_language", h.HandleSetLanguage)
	mux.HandleFunc("GET /api/set_language", h.HandleSetLanguage)

	return mux
}
