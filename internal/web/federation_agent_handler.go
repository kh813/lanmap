package web

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"lanmap/internal/db"
	"lanmap/internal/federation"
	"lanmap/internal/i18n"
)

// AgentTabViewModel holds rendering data for the Federation Agent tab
type AgentTabViewModel struct {
	Lang          string
	Status        string // "standalone", "waiting", "connected"
	AgentConfig   *federation.AgentConfig
	AgentLastSync string
	Message       string
	ErrorMessage  string
	ServerURL     string
	PIN           string
	AgentID       string
	AgentName     string
	CIDR          string
	PollElapsed   int
}

// HandleAgentPairRequest initiates a pairing request from this agent instance to a parent server
func (h *Handler) HandleAgentPairRequest(w http.ResponseWriter, r *http.Request) {
	lang := i18n.DetectLanguage(r)
	_ = r.ParseForm()

	serverURL := strings.TrimSpace(r.FormValue("server_url"))
	pin := strings.TrimSpace(r.FormValue("pin"))
	name := strings.TrimSpace(r.FormValue("name"))
	cidr := strings.TrimSpace(r.FormValue("cidr"))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if serverURL == "" || pin == "" {
		vm := AgentTabViewModel{
			Lang:         lang,
			Status:       "standalone",
			ServerURL:    serverURL,
			PIN:          pin,
			AgentName:    name,
			CIDR:         cidr,
			ErrorMessage: "親機サーバーURLとワンタイムPINは必須です。",
		}
		_ = h.tmpl.ExecuteTemplate(w, "agent_settings_tab.html", vm)
		return
	}

	// Normalize Server URL
	if !strings.HasPrefix(serverURL, "http://") && !strings.HasPrefix(serverURL, "https://") {
		serverURL = "https://" + serverURL
	}
	serverURL = strings.TrimRight(serverURL, "/")

	// Default agent name to hostname if empty
	if name == "" {
		if hName, err := os.Hostname(); err == nil && hName != "" {
			name = hName
		} else {
			name = "Remote Site"
		}
	}

	// Send POST /api/federation/pair/request to central server
	client := federation.GetHTTPClient()
	reqPayload := federation.PairRequestPayload{
		PIN:     pin,
		Name:    name,
		Version: h.cfg.Version,
		CIDR:    cidr,
	}
	bodyBytes, err := json.Marshal(reqPayload)
	if err != nil {
		vm := AgentTabViewModel{
			Lang:         lang,
			Status:       "standalone",
			ServerURL:    serverURL,
			PIN:          pin,
			AgentName:    name,
			CIDR:         cidr,
			ErrorMessage: fmt.Sprintf("リクエストの作成に失敗しました: %v", err),
		}
		_ = h.tmpl.ExecuteTemplate(w, "agent_settings_tab.html", vm)
		return
	}

	req, err := http.NewRequestWithContext(r.Context(), "POST", serverURL+"/api/federation/pair/request", bytes.NewReader(bodyBytes))
	if err != nil {
		vm := AgentTabViewModel{
			Lang:         lang,
			Status:       "standalone",
			ServerURL:    serverURL,
			PIN:          pin,
			AgentName:    name,
			CIDR:         cidr,
			ErrorMessage: fmt.Sprintf("リクエストの初期化に失敗しました: %v", err),
		}
		_ = h.tmpl.ExecuteTemplate(w, "agent_settings_tab.html", vm)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		vm := AgentTabViewModel{
			Lang:         lang,
			Status:       "standalone",
			ServerURL:    serverURL,
			PIN:          pin,
			AgentName:    name,
			CIDR:         cidr,
			ErrorMessage: fmt.Sprintf("親機サーバー (%s) への接続に失敗しました: %v", serverURL, err),
		}
		_ = h.tmpl.ExecuteTemplate(w, "agent_settings_tab.html", vm)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		vm := AgentTabViewModel{
			Lang:         lang,
			Status:       "standalone",
			ServerURL:    serverURL,
			PIN:          pin,
			AgentName:    name,
			CIDR:         cidr,
			ErrorMessage: fmt.Sprintf("親機サーバーでの参加要求に失敗しました (HTTP %d): %s", resp.StatusCode, string(respBody)),
		}
		_ = h.tmpl.ExecuteTemplate(w, "agent_settings_tab.html", vm)
		return
	}

	var pairResp federation.PairRequestResponse
	if err := json.NewDecoder(resp.Body).Decode(&pairResp); err != nil {
		vm := AgentTabViewModel{
			Lang:         lang,
			Status:       "standalone",
			ServerURL:    serverURL,
			PIN:          pin,
			AgentName:    name,
			CIDR:         cidr,
			ErrorMessage: fmt.Sprintf("親機の応答デコードに失敗しました: %v", err),
		}
		_ = h.tmpl.ExecuteTemplate(w, "agent_settings_tab.html", vm)
		return
	}

	// Render waiting state
	vm := AgentTabViewModel{
		Lang:        lang,
		Status:      "waiting",
		ServerURL:   serverURL,
		PIN:         pin,
		AgentID:     pairResp.AgentID,
		AgentName:   name,
		CIDR:        cidr,
		PollElapsed: 3,
	}
	_ = h.tmpl.ExecuteTemplate(w, "agent_settings_tab.html", vm)
}

// HandleAgentPairPoll is called via HTMX polling to check approval status from the parent server
func (h *Handler) HandleAgentPairPoll(w http.ResponseWriter, r *http.Request) {
	lang := i18n.DetectLanguage(r)
	serverURL := strings.TrimSpace(r.URL.Query().Get("server_url"))
	pin := strings.TrimSpace(r.URL.Query().Get("pin"))
	agentID := strings.TrimSpace(r.URL.Query().Get("agent_id"))
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	elapsedStr := r.URL.Query().Get("elapsed")
	elapsed, _ := strconv.Atoi(elapsedStr)
	elapsed += 3

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	// Timeout check: 3 minutes (180 seconds)
	if elapsed > 180 {
		vm := AgentTabViewModel{
			Lang:         lang,
			Status:       "standalone",
			ServerURL:    serverURL,
			PIN:          pin,
			AgentName:    name,
			ErrorMessage: "親機サーバーでの承認待機がタイムアウトしました（3分間承認がありませんでした）。もう一度お試しください。",
		}
		_ = h.tmpl.ExecuteTemplate(w, "agent_settings_tab.html", vm)
		return
	}

	client := federation.GetHTTPClient()
	statusURL := fmt.Sprintf("%s/api/federation/pair/status?pin=%s&agent_id=%s", serverURL, pin, agentID)
	statusReq, err := http.NewRequestWithContext(r.Context(), "GET", statusURL, nil)
	if err != nil {
		// Retry waiting
		vm := AgentTabViewModel{
			Lang:        lang,
			Status:      "waiting",
			ServerURL:   serverURL,
			PIN:         pin,
			AgentID:     agentID,
			AgentName:   name,
			PollElapsed: elapsed,
		}
		_ = h.tmpl.ExecuteTemplate(w, "agent_settings_tab.html", vm)
		return
	}

	sResp, err := client.Do(statusReq)
	if err != nil {
		// Transient network error, retry waiting
		vm := AgentTabViewModel{
			Lang:        lang,
			Status:      "waiting",
			ServerURL:   serverURL,
			PIN:         pin,
			AgentID:     agentID,
			AgentName:   name,
			PollElapsed: elapsed,
		}
		_ = h.tmpl.ExecuteTemplate(w, "agent_settings_tab.html", vm)
		return
	}
	defer sResp.Body.Close()

	var stat federation.PairStatusResponse
	_ = json.NewDecoder(sResp.Body).Decode(&stat)

	switch stat.Status {
	case "approved":
		if stat.Token == "" {
			vm := AgentTabViewModel{
				Lang:         lang,
				Status:       "standalone",
				ServerURL:    serverURL,
				PIN:          pin,
				AgentName:    name,
				ErrorMessage: "承認を受領しましたが、認証トークンが空でした。",
			}
			_ = h.tmpl.ExecuteTemplate(w, "agent_settings_tab.html", vm)
			return
		}

		cfg := &federation.AgentConfig{
			ServerURL: serverURL,
			Token:     stat.Token,
			AgentID:   agentID,
			AgentName: name,
		}
		if err := federation.SaveAgentConfig(h.db, cfg); err != nil {
			vm := AgentTabViewModel{
				Lang:         lang,
				Status:       "standalone",
				ServerURL:    serverURL,
				PIN:          pin,
				AgentName:    name,
				ErrorMessage: fmt.Sprintf("設定の保存に失敗しました: %v", err),
			}
			_ = h.tmpl.ExecuteTemplate(w, "agent_settings_tab.html", vm)
			return
		}

		// Push initial report in background
		go func() {
			hosts, err := h.db.ListHostsFilteredWithAgent(nil, "all", 0, nil)
			if err != nil {
				return
			}
			var hostList []db.Host
			for _, hst := range hosts {
				if hst != nil {
					hostList = append(hostList, *hst)
				}
			}
			payload := federation.ReportPayload{
				AgentID:       agentID,
				AgentName:     name,
				AgentVersion:  h.cfg.Version,
				SchemaVersion: federation.CurrentSchemaVersion,
				ReportedAt:    time.Now(),
				Hosts:         hostList,
			}
			if _, err := federation.PushReport(r.Context(), serverURL, stat.Token, payload); err == nil {
				_ = h.db.SetSetting("agent_last_sync", time.Now().Format("2006-01-02 15:04:05"))
			}
		}()

		vm := AgentTabViewModel{
			Lang:        lang,
			Status:      "connected",
			AgentConfig: cfg,
			Message:     "親機サーバーとのペアリングが完了しました！拠点エージェントモードで動作中",
		}
		_ = h.tmpl.ExecuteTemplate(w, "agent_settings_tab.html", vm)
		return

	case "rejected":
		vm := AgentTabViewModel{
			Lang:         lang,
			Status:       "standalone",
			ServerURL:    serverURL,
			PIN:          pin,
			AgentName:    name,
			ErrorMessage: "親機の管理者によって参加要求が拒否されました。",
		}
		_ = h.tmpl.ExecuteTemplate(w, "agent_settings_tab.html", vm)
		return

	case "expired":
		vm := AgentTabViewModel{
			Lang:         lang,
			Status:       "standalone",
			ServerURL:    serverURL,
			PIN:          pin,
			AgentName:    name,
			ErrorMessage: "ペアリング用PINの有効期限（15分）が切れました。親機で再発行してください。",
		}
		_ = h.tmpl.ExecuteTemplate(w, "agent_settings_tab.html", vm)
		return

	case "not_found":
		vm := AgentTabViewModel{
			Lang:         lang,
			Status:       "standalone",
			ServerURL:    serverURL,
			PIN:          pin,
			AgentName:    name,
			ErrorMessage: "参加要求が見つかりませんでした。再度ペアリングを開始してください。",
		}
		_ = h.tmpl.ExecuteTemplate(w, "agent_settings_tab.html", vm)
		return

	default: // "pending", "issued", "requested"
		vm := AgentTabViewModel{
			Lang:        lang,
			Status:      "waiting",
			ServerURL:   serverURL,
			PIN:         pin,
			AgentID:     agentID,
			AgentName:   name,
			PollElapsed: elapsed,
		}
		_ = h.tmpl.ExecuteTemplate(w, "agent_settings_tab.html", vm)
		return
	}
}

// HandleAgentUnpair disconnects this agent from the parent server
func (h *Handler) HandleAgentUnpair(w http.ResponseWriter, r *http.Request) {
	lang := i18n.DetectLanguage(r)
	_ = federation.ClearAgentConfig(h.db)
	_ = h.db.SetSetting("agent_last_sync", "")

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	vm := AgentTabViewModel{
		Lang:    lang,
		Status:  "standalone",
		Message: i18n.T(lang, "agent_unpaired_success"),
	}
	_ = h.tmpl.ExecuteTemplate(w, "agent_settings_tab.html", vm)
}

// HandleAgentCancel cancels a waiting pairing request
func (h *Handler) HandleAgentCancel(w http.ResponseWriter, r *http.Request) {
	lang := i18n.DetectLanguage(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	vm := AgentTabViewModel{
		Lang:   lang,
		Status: "standalone",
	}
	_ = h.tmpl.ExecuteTemplate(w, "agent_settings_tab.html", vm)
}

// HandleAgentManualReport triggers an immediate report push to the central server
func (h *Handler) HandleAgentManualReport(w http.ResponseWriter, r *http.Request) {
	lang := i18n.DetectLanguage(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	agentCfg, err := federation.LoadAgentConfig(h.db)
	if err != nil || agentCfg == nil || !agentCfg.IsPaired() {
		vm := AgentTabViewModel{
			Lang:         lang,
			Status:       "standalone",
			ErrorMessage: "エージェント設定が構成されていません。",
		}
		_ = h.tmpl.ExecuteTemplate(w, "agent_settings_tab.html", vm)
		return
	}

	hosts, err := h.db.ListHostsFilteredWithAgent(nil, "all", 0, nil)
	if err != nil {
		vm := AgentTabViewModel{
			Lang:         lang,
			Status:       "connected",
			AgentConfig:  agentCfg,
			ErrorMessage: fmt.Sprintf("ローカル端末一覧の取得に失敗しました: %v", err),
		}
		_ = h.tmpl.ExecuteTemplate(w, "agent_settings_tab.html", vm)
		return
	}

	var hostList []db.Host
	for _, hst := range hosts {
		if hst != nil {
			hostList = append(hostList, *hst)
		}
	}

	payload := federation.ReportPayload{
		AgentID:       agentCfg.AgentID,
		AgentName:     agentCfg.AgentName,
		AgentVersion:  h.cfg.Version,
		SchemaVersion: federation.CurrentSchemaVersion,
		ReportedAt:    time.Now(),
		Hosts:         hostList,
	}

	resp, err := federation.PushReport(r.Context(), agentCfg.ServerURL, agentCfg.Token, payload)
	if err != nil {
		lastSync, _ := h.db.GetSetting("agent_last_sync")
		vm := AgentTabViewModel{
			Lang:          lang,
			Status:        "connected",
			AgentConfig:   agentCfg,
			AgentLastSync: lastSync,
			ErrorMessage:  fmt.Sprintf(i18n.T(lang, "agent_report_failed"), err.Error()),
		}
		_ = h.tmpl.ExecuteTemplate(w, "agent_settings_tab.html", vm)
		return
	}

	nowStr := time.Now().Format("2006-01-02 15:04:05")
	_ = h.db.SetSetting("agent_last_sync", nowStr)

	msg := fmt.Sprintf(i18n.T(lang, "agent_report_success"), len(hostList))
	if resp.VersionMismatch {
		msg += fmt.Sprintf(" (⚠️ %s)", resp.Message)
	}

	vm := AgentTabViewModel{
		Lang:          lang,
		Status:        "connected",
		AgentConfig:   agentCfg,
		AgentLastSync: nowStr,
		Message:       msg,
	}
	_ = h.tmpl.ExecuteTemplate(w, "agent_settings_tab.html", vm)
}
