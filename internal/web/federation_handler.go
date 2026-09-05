package web

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"lanmap/internal/db"
	"lanmap/internal/federation"
	"lanmap/internal/i18n"
)

// getClientIP extracts real remote IP from headers or connection
func getClientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	if xrip := r.Header.Get("X-Real-IP"); xrip != "" {
		return strings.TrimSpace(xrip)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

// HandleFederationModal renders the federation management modal
func (h *Handler) HandleFederationModal(w http.ResponseWriter, r *http.Request) {
	lang := i18n.DetectLanguage(r)
	agents, err := h.db.ListAgents()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	pending, err := h.db.ListPendingPairingRequests()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	data := struct {
		Lang          string
		Agents        []db.FederationAgent
		Pending       []db.FederationPairingPIN
		ServerVersion string
	}{
		Lang:          lang,
		Agents:        agents,
		Pending:       pending,
		ServerVersion: h.cfg.Version,
	}

	if err := h.tmpl.ExecuteTemplate(w, "federation_modal.html", data); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// HandleStartPairing issues a new 6-digit PIN (valid for 15 minutes)
func (h *Handler) HandleStartPairing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	agentName := strings.TrimSpace(r.FormValue("name"))
	if agentName == "" {
		agentName = "Remote Site"
	}

	pinObj, err := h.db.CreatePairingPIN(agentName)
	if err != nil {
		http.Error(w, fmt.Sprintf("Failed to create pairing PIN: %v", err), http.StatusInternalServerError)
		return
	}

	// If requested via JSON
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(federation.PairStartResponse{
			PIN:       pinObj.PIN,
			ExpiresAt: pinObj.ExpiresAt,
			Message:   "PIN generated successfully. Use this PIN on remote agent within 15 minutes.",
		})
		return
	}

	// Render PIN display section for modal
	lang := i18n.DetectLanguage(r)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	data := struct {
		Lang      string
		PIN       string
		AgentName string
		ExpiresAt time.Time
		HostURL   string
	}{
		Lang:      lang,
		PIN:       pinObj.PIN,
		AgentName: agentName,
		ExpiresAt: pinObj.ExpiresAt,
		HostURL:   r.Host,
	}

	_ = h.tmpl.ExecuteTemplate(w, "federation_pin_display", data)
}

// HandleRequestPairing is called by an agent to request pairing with a PIN
func (h *Handler) HandleRequestPairing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload federation.PairRequestPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Invalid request payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	if payload.PIN == "" {
		http.Error(w, "PIN is required", http.StatusBadRequest)
		return
	}

	remoteIP := getClientIP(r)
	agentID, err := h.db.RequestPairing(payload.PIN, payload.Name, payload.Version, payload.CIDR, remoteIP)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(federation.PairRequestResponse{
		AgentID: agentID,
		Status:  "requested",
		Message: "Pairing requested. Awaiting administrator approval in server Web UI.",
	})
}

// HandlePairingStatus is polled by the remote agent to check approval status
func (h *Handler) HandlePairingStatus(w http.ResponseWriter, r *http.Request) {
	pin := strings.TrimSpace(r.URL.Query().Get("pin"))
	agentID := strings.TrimSpace(r.URL.Query().Get("agent_id"))

	if pin == "" {
		http.Error(w, "pin is required", http.StatusBadRequest)
		return
	}

	status, token, err := h.db.GetPairingStatus(pin, agentID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(federation.PairStatusResponse{
		Status: status,
		Token:  token,
	})
}

// HandleApprovePairing approves a pending pairing request and issues a token
func (h *Handler) HandleApprovePairing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	pin := strings.TrimSpace(r.FormValue("pin"))
	if pin == "" {
		var payload federation.PairApprovePayload
		_ = json.NewDecoder(r.Body).Decode(&payload)
		pin = strings.TrimSpace(payload.PIN)
	}

	if pin == "" {
		http.Error(w, "PIN is required", http.StatusBadRequest)
		return
	}

	_, err := h.db.ApprovePairing(pin)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Trigger sidebar and modal refresh in Web UI
	w.Header().Set("HX-Trigger", "refreshSidebar")
	h.HandleFederationModal(w, r)
}

// HandleRejectPairing rejects a pending pairing request
func (h *Handler) HandleRejectPairing(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	pin := strings.TrimSpace(r.FormValue("pin"))
	if pin == "" {
		var payload federation.PairApprovePayload
		_ = json.NewDecoder(r.Body).Decode(&payload)
		pin = strings.TrimSpace(payload.PIN)
	}

	if pin != "" {
		_ = h.db.RejectPairing(pin)
	}

	w.Header().Set("HX-Trigger", "refreshSidebar")
	h.HandleFederationModal(w, r)
}

// HandleRevokeAgent invalidates an agent's token
func (h *Handler) HandleRevokeAgent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	agentID := r.PathValue("id")
	if agentID == "" {
		http.Error(w, "Agent ID is required", http.StatusBadRequest)
		return
	}

	if err := h.db.RevokeAgent(agentID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("HX-Trigger", "refreshSidebar")
	h.HandleFederationModal(w, r)
}

// HandleDeleteAgent removes the agent and all its remote hosts
func (h *Handler) HandleDeleteAgent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete && r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	agentID := r.PathValue("id")
	if agentID == "" {
		http.Error(w, "Agent ID is required", http.StatusBadRequest)
		return
	}

	if err := h.db.DeleteAgent(agentID); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("HX-Trigger", "refreshSidebar")
	h.HandleFederationModal(w, r)
}

// HandleFederationReport accepts periodic network reports from authenticated agents
func (h *Handler) HandleFederationReport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// 1. Authenticate Bearer Token
	authHeader := r.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		http.Error(w, "Missing or invalid Authorization header", http.StatusUnauthorized)
		return
	}
	token := strings.TrimPrefix(authHeader, "Bearer ")
	tokenHash := db.HashToken(token)

	agent, err := h.db.GetAgentByTokenHash(tokenHash)
	if err != nil || agent == nil {
		http.Error(w, "Invalid or revoked agent token", http.StatusUnauthorized)
		return
	}

	// 2. Decode Report Payload
	var payload federation.ReportPayload
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "Failed to decode report payload: "+err.Error(), http.StatusBadRequest)
		return
	}

	// 3. Version Compatibility Check
	versionMismatch, vErr := federation.CheckVersionCompatibility(h.cfg.Version, payload.AgentVersion)
	if vErr != nil {
		// Major version mismatch - incompatible!
		http.Error(w, "Incompatible agent version: "+vErr.Error(), http.StatusUpgradeRequired)
		return
	}

	// 4. Update Agent Heartbeat
	remoteIP := getClientIP(r)
	_ = h.db.UpdateAgentHeartbeat(agent.ID, remoteIP, payload.AgentVersion, payload.SchemaVersion, versionMismatch)

	// 5. Ingest Remote Hosts (isolated by agent.ID)
	if err := h.db.UpsertRemoteHosts(agent.ID, payload.Hosts); err != nil {
		http.Error(w, "Failed to ingest hosts: "+err.Error(), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(federation.ReportResponse{
		Success:         true,
		VersionMismatch: versionMismatch,
		Message:         fmt.Sprintf("Report ingested successfully (%d hosts)", len(payload.Hosts)),
	})
}
