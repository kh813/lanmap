package federation_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"lanmap/internal/config"
	"lanmap/internal/db"
	"lanmap/internal/federation"
	"lanmap/internal/notifier"
	"lanmap/internal/scanner"
	"lanmap/internal/web"
)

type inProcessTransport struct {
	handler http.Handler
}

func (t *inProcessTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	rec := httptest.NewRecorder()
	t.handler.ServeHTTP(rec, req)
	return rec.Result(), nil
}

// setupServerEnv creates a full lanmap server instance running in-memory without binding external sockets
func setupServerEnv(t *testing.T, serverVersion string) (string, *http.Client, *db.DB) {
	t.Helper()
	serverDir := t.TempDir()
	serverDBPath := filepath.Join(serverDir, "server.db")
	serverDB, err := db.Open(serverDBPath)
	if err != nil {
		t.Fatalf("setup server db failed: %v", err)
	}
	t.Cleanup(func() { serverDB.Close() })

	cfg := &config.Config{
		HTTPPort:        3002,
		ScanConcurrency: 5,
		Version:         serverVersion,
	}

	sc := scanner.NewScanner(serverDB, cfg)
	notif := notifier.NewNotifier(serverDB)

	handler, err := web.NewHandler(serverDB, cfg, sc, notif)
	if err != nil {
		t.Fatalf("setup server handler failed: %v", err)
	}

	router := web.NewRouter(handler)
	fakeServerURL := "http://lanmap.internal:3002"

	client := &http.Client{
		Transport: &inProcessTransport{handler: router},
	}
	federation.SetCustomHTTPClient(client)
	t.Cleanup(func() { federation.SetCustomHTTPClient(nil) })

	return fakeServerURL, client, serverDB
}

// setupAgentEnv creates an independent agent database
func setupAgentEnv(t *testing.T) *db.DB {
	t.Helper()
	agentDir := t.TempDir()
	agentDBPath := filepath.Join(agentDir, "agent.db")
	agentDB, err := db.Open(agentDBPath)
	if err != nil {
		t.Fatalf("setup agent db failed: %v", err)
	}
	t.Cleanup(func() { agentDB.Close() })
	return agentDB
}

// TestFederationFullLifecycleE2E verifies the entire real-world lifecycle between an agent node and central server:
// PIN Generation -> Agent Pair Request -> Polling -> Admin Web Approval -> Token Store -> Push Report -> Host Isolation -> Revoke -> 401 Rejection -> Unpair
func TestFederationFullLifecycleE2E(t *testing.T) {
	serverURL, client, serverDB := setupServerEnv(t, "v0.0.16")
	agentDB := setupAgentEnv(t)

	// 1. Initial State: Agent is not paired
	cfg, err := federation.LoadAgentConfig(agentDB)
	if err != nil {
		t.Fatalf("LoadAgentConfig failed: %v", err)
	}
	if cfg.IsPaired() {
		t.Fatal("expected agent not to be paired initially")
	}

	// 2. Server Admin generates 6-digit PIN via Web UI
	pinObj, err := serverDB.CreatePairingPIN("大阪支社")
	if err != nil {
		t.Fatalf("CreatePairingPIN failed: %v", err)
	}
	if len(pinObj.PIN) != 6 {
		t.Fatalf("expected 6-digit PIN, got %s", pinObj.PIN)
	}

	// 3. Agent runs pairing process with polling in a background goroutine
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	var pairResult *federation.AgentConfig
	var pairErr error
	var wg sync.WaitGroup
	waitingReported := make(chan string, 1)

	wg.Add(1)
	go func() {
		defer wg.Done()
		pairResult, pairErr = federation.Pair(ctx, serverURL, pinObj.PIN, "大阪支社", "v0.0.16", "192.168.20.0/24", func(agentID string) {
			waitingReported <- agentID
		})
	}()

	// Wait for agent to report it sent request and is now waiting for approval
	var agentID string
	select {
	case agentID = <-waitingReported:
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for agent to send pairing request")
	}

	if agentID == "" {
		t.Fatal("expected non-empty agentID from waiting callback")
	}

	// Verify server sees pending request
	pending, err := serverDB.ListPendingPairingRequests()
	if err != nil || len(pending) != 1 {
		t.Fatalf("expected 1 pending request on server, got %d, err=%v", len(pending), err)
	}
	if pending[0].AgentID != agentID || pending[0].AgentName != "大阪支社" {
		t.Fatalf("unexpected pending request details: %+v", pending[0])
	}

	// 4. Server Admin clicks "Approve" via HTTP POST
	approveForm := url.Values{"pin": {pinObj.PIN}}
	approveResp, err := client.PostForm(serverURL+"/api/federation/pair/approve", approveForm)
	if err != nil {
		t.Fatalf("POST /api/federation/pair/approve failed: %v", err)
	}
	approveResp.Body.Close()
	if approveResp.StatusCode != http.StatusOK {
		t.Fatalf("approve HTTP status: %d", approveResp.StatusCode)
	}

	// 5. Agent finishes pairing and receives Bearer token
	wg.Wait()
	if pairErr != nil {
		t.Fatalf("federation.Pair failed: %v", pairErr)
	}
	if pairResult == nil || pairResult.Token == "" {
		t.Fatal("expected non-empty token from federation.Pair")
	}
	if pairResult.AgentID != agentID {
		t.Fatalf("expected agentID %s, got %s", agentID, pairResult.AgentID)
	}

	// Save agent configuration to agent's local DB
	if err := federation.SaveAgentConfig(agentDB, pairResult); err != nil {
		t.Fatalf("SaveAgentConfig failed: %v", err)
	}

	loadedCfg, err := federation.LoadAgentConfig(agentDB)
	if err != nil || !loadedCfg.IsPaired() {
		t.Fatalf("expected agent to be paired in DB, got: %+v", loadedCfg)
	}

	// 6. Push Network Report from Agent to Server
	agentHosts := []db.Host{
		{
			IP:          "192.168.20.1",
			MACAddress:  "aa:bb:cc:00:00:01",
			Hostname:    "osaka-router",
			DisplayName: "大阪ルーター",
			Status:      "up",
		},
		{
			IP:          "192.168.20.50",
			MACAddress:  "aa:bb:cc:00:00:02",
			Hostname:    "osaka-fileserver",
			DisplayName: "大阪ファイルサーバー",
			Status:      "up",
		},
	}

	reportPayload := federation.ReportPayload{
		AgentID:       loadedCfg.AgentID,
		AgentName:     loadedCfg.AgentName,
		AgentVersion:  "v0.0.16",
		SchemaVersion: federation.CurrentSchemaVersion,
		CIDR:          "192.168.20.0/24",
		ReportedAt:    time.Now(),
		Hosts:         agentHosts,
	}

	repResp, err := federation.PushReport(ctx, loadedCfg.ServerURL, loadedCfg.Token, reportPayload)
	if err != nil {
		t.Fatalf("PushReport failed: %v", err)
	}
	if !repResp.Success {
		t.Fatalf("expected success, got message: %s", repResp.Message)
	}
	if repResp.VersionMismatch {
		t.Fatalf("expected version_mismatch=false for matching version v0.0.16")
	}

	// 7. Verify Server Database State
	serverAgent, err := serverDB.GetAgentByID(agentID)
	if err != nil || serverAgent == nil {
		t.Fatalf("GetAgentByID failed: %v", err)
	}
	if serverAgent.Status != "active" {
		t.Fatalf("expected server agent status 'active', got '%s'", serverAgent.Status)
	}
	if serverAgent.LastSeenAt == nil {
		t.Fatal("expected LastSeenAt to be updated on server")
	}

	// Query remote hosts scoped to this agent
	reportedHosts, err := serverDB.ListHostsFilteredWithAgent(nil, "all", 0, &agentID)
	if err != nil {
		t.Fatalf("ListHostsFilteredWithAgent failed: %v", err)
	}
	if len(reportedHosts) != 2 {
		t.Fatalf("expected 2 remote hosts on server, got %d", len(reportedHosts))
	}
	if reportedHosts[0].AgentName != "大阪支社" {
		t.Fatalf("expected AgentName '大阪支社', got '%s'", reportedHosts[0].AgentName)
	}

	// Query local hosts (agentID == nil) - must NOT contain remote hosts!
	localHosts, err := serverDB.ListHostsFilteredWithAgent(nil, "all", 0, nil)
	if err != nil {
		t.Fatalf("ListHostsFilteredWithAgent local failed: %v", err)
	}
	if len(localHosts) != 0 {
		t.Fatalf("expected 0 local hosts on fresh server, got %d", len(localHosts))
	}

	// 8. Admin revokes the Agent
	revokeURL := fmt.Sprintf("%s/api/federation/agents/%s/revoke", serverURL, agentID)
	revResp, err := client.Post(revokeURL, "application/x-www-form-urlencoded", nil)
	if err != nil {
		t.Fatalf("POST revoke failed: %v", err)
	}
	revResp.Body.Close()
	if revResp.StatusCode != http.StatusOK {
		t.Fatalf("revoke HTTP status: %d", revResp.StatusCode)
	}

	// 9. Subsequent PushReport from agent must be rejected with HTTP 401 Unauthorized
	_, repErrAfterRevoke := federation.PushReport(ctx, loadedCfg.ServerURL, loadedCfg.Token, reportPayload)
	if repErrAfterRevoke == nil {
		t.Fatal("expected PushReport to fail after revocation, but it succeeded")
	}
	if !strings.Contains(repErrAfterRevoke.Error(), "401") {
		t.Fatalf("expected 401 Unauthorized error, got: %v", repErrAfterRevoke)
	}

	// 10. Agent executes Unpair
	if err := federation.ClearAgentConfig(agentDB); err != nil {
		t.Fatalf("ClearAgentConfig failed: %v", err)
	}
	afterUnpair, err := federation.LoadAgentConfig(agentDB)
	if err != nil || afterUnpair.IsPaired() {
		t.Fatalf("expected agent to be unpaired, got: %+v", afterUnpair)
	}
}

// TestFederationMultiSiteIPConflictE2E ensures multiple remote sites and central server
// sharing identical private IP addresses (e.g. 192.168.1.1, 192.168.1.50) never conflict or overwrite each other
func TestFederationMultiSiteIPConflictE2E(t *testing.T) {
	serverURL, _, serverDB := setupServerEnv(t, "v0.0.16")
	ctx := context.Background()

	// 1. Register Site A (Tokyo HQ - Local Server)
	localHost := &db.Host{
		IP:          "192.168.1.50",
		MACAddress:  "00:11:22:33:44:00",
		Hostname:    "hq-server",
		DisplayName: "本社メインサーバー",
		Status:      "up",
	}
	_, _, err := serverDB.UpsertHostOnScan(localHost)
	if err != nil {
		t.Fatalf("UpsertHostOnScan local failed: %v", err)
	}

	// 2. Register Site B (Osaka Branch)
	pinOsaka, _ := serverDB.CreatePairingPIN("大阪支社")
	osakaAgentID, _ := serverDB.RequestPairing(pinOsaka.PIN, "大阪支社", "v0.0.16", "192.168.1.0/24", "100.64.0.2")
	osakaToken, _ := serverDB.ApprovePairing(pinOsaka.PIN)

	// 3. Register Site C (Nagoya Branch)
	pinNagoya, _ := serverDB.CreatePairingPIN("名古屋支社")
	nagoyaAgentID, _ := serverDB.RequestPairing(pinNagoya.PIN, "名古屋支社", "v0.0.16", "192.168.1.0/24", "100.64.0.3")
	nagoyaToken, _ := serverDB.ApprovePairing(pinNagoya.PIN)

	// 4. Osaka pushes hosts containing the EXACT SAME IP (192.168.1.50)
	osakaHosts := []db.Host{
		{
			IP:          "192.168.1.50",
			MACAddress:  "00:11:22:33:44:01",
			Hostname:    "osaka-printer",
			DisplayName: "大阪プリンター",
			Status:      "up",
		},
	}
	_, err = federation.PushReport(ctx, serverURL, osakaToken, federation.ReportPayload{
		AgentID:       osakaAgentID,
		AgentName:     "大阪支社",
		AgentVersion:  "v0.0.16",
		SchemaVersion: 1,
		Hosts:         osakaHosts,
	})
	if err != nil {
		t.Fatalf("Osaka PushReport failed: %v", err)
	}

	// 5. Nagoya pushes hosts also containing the EXACT SAME IP (192.168.1.50)
	nagoyaHosts := []db.Host{
		{
			IP:          "192.168.1.50",
			MACAddress:  "00:11:22:33:44:02",
			Hostname:    "nagoya-nas",
			DisplayName: "名古屋ファイルNAS",
			Status:      "up",
		},
	}
	_, err = federation.PushReport(ctx, serverURL, nagoyaToken, federation.ReportPayload{
		AgentID:       nagoyaAgentID,
		AgentName:     "名古屋支社",
		AgentVersion:  "v0.0.16",
		SchemaVersion: 1,
		Hosts:         nagoyaHosts,
	})
	if err != nil {
		t.Fatalf("Nagoya PushReport failed: %v", err)
	}

	// 6. Verify Complete Isolation
	// (a) Local Server View: Only 本社メインサーバー
	hLocal, err := serverDB.ListHostsFilteredWithAgent(nil, "all", 0, nil)
	if err != nil || len(hLocal) != 1 {
		t.Fatalf("expected 1 local host, got %d, err=%v", len(hLocal), err)
	}
	if hLocal[0].Hostname != "hq-server" || hLocal[0].DisplayName != "本社メインサーバー" {
		t.Fatalf("local host overwritten: %+v", hLocal[0])
	}

	// (b) Osaka View: Only 大阪プリンター
	hOsaka, err := serverDB.ListHostsFilteredWithAgent(nil, "all", 0, &osakaAgentID)
	if err != nil || len(hOsaka) != 1 {
		t.Fatalf("expected 1 osaka host, got %d, err=%v", len(hOsaka), err)
	}
	if hOsaka[0].Hostname != "osaka-printer" || hOsaka[0].DisplayName != "大阪プリンター" {
		t.Fatalf("osaka host overwritten: %+v", hOsaka[0])
	}

	// (c) Nagoya View: Only 名古屋ファイルNAS
	hNagoya, err := serverDB.ListHostsFilteredWithAgent(nil, "all", 0, &nagoyaAgentID)
	if err != nil || len(hNagoya) != 1 {
		t.Fatalf("expected 1 nagoya host, got %d, err=%v", len(hNagoya), err)
	}
	if hNagoya[0].Hostname != "nagoya-nas" || hNagoya[0].DisplayName != "名古屋ファイルNAS" {
		t.Fatalf("nagoya host overwritten: %+v", hNagoya[0])
	}

	// (d) All Sites View (*): Exactly 3 distinct records with identical IP 192.168.1.50
	allScope := "*"
	hAll, err := serverDB.ListHostsFilteredWithAgent(nil, "all", 0, &allScope)
	if err != nil || len(hAll) != 3 {
		t.Fatalf("expected 3 hosts in all scope, got %d, err=%v", len(hAll), err)
	}

	namesFound := make(map[string]bool)
	for _, h := range hAll {
		namesFound[h.Hostname] = true
	}
	if !namesFound["hq-server"] || !namesFound["osaka-printer"] || !namesFound["nagoya-nas"] {
		t.Fatalf("missing hosts in all view: %+v", namesFound)
	}
}

// TestFederationVersionCompatibilityE2E verifies semantic version compatibility handling
func TestFederationVersionCompatibilityE2E(t *testing.T) {
	serverURL, _, serverDB := setupServerEnv(t, "v0.0.16")
	ctx := context.Background()

	pin, _ := serverDB.CreatePairingPIN("互換性テスト拠点")
	agentID, _ := serverDB.RequestPairing(pin.PIN, "互換性テスト拠点", "v0.0.16", "192.168.30.0/24", "100.64.0.9")
	token, _ := serverDB.ApprovePairing(pin.PIN)

	// 1. Minor/Patch mismatch: Server v0.0.16 vs Agent v0.0.18 -> Accepted with version_mismatch=true
	repResp, err := federation.PushReport(ctx, serverURL, token, federation.ReportPayload{
		AgentID:       agentID,
		AgentName:     "互換性テスト拠点",
		AgentVersion:  "v0.0.18",
		SchemaVersion: 1,
		Hosts:         []db.Host{{IP: "192.168.30.1", Status: "up"}},
	})
	if err != nil {
		t.Fatalf("minor version mismatch report failed: %v", err)
	}
	if !repResp.VersionMismatch {
		t.Fatal("expected VersionMismatch=true for v0.0.18 vs v0.0.16")
	}

	// Server agent record must reflect VersionMismatch
	agentRecord, _ := serverDB.GetAgentByID(agentID)
	if !agentRecord.VersionMismatch {
		t.Fatal("expected server DB record VersionMismatch=true")
	}
	if agentRecord.Version != "v0.0.18" {
		t.Fatalf("expected server DB record Version='v0.0.18', got '%s'", agentRecord.Version)
	}

	// 2. Major mismatch: Server v0.0.16 vs Agent v1.0.0 -> Rejected with HTTP 426 Upgrade Required
	_, errMajor := federation.PushReport(ctx, serverURL, token, federation.ReportPayload{
		AgentID:       agentID,
		AgentName:     "互換性テスト拠点",
		AgentVersion:  "v1.0.0",
		SchemaVersion: 1,
		Hosts:         []db.Host{{IP: "192.168.30.1", Status: "up"}},
	})
	if errMajor == nil {
		t.Fatal("expected major version mismatch to be rejected, but it succeeded")
	}
	if !strings.Contains(errMajor.Error(), "426") {
		t.Fatalf("expected HTTP 426 error, got: %v", errMajor)
	}
}

// TestFederationSecurityRejectionsE2E verifies security boundary protection
func TestFederationSecurityRejectionsE2E(t *testing.T) {
	serverURL, _, serverDB := setupServerEnv(t, "v0.0.16")
	ctx := context.Background()

	// 1. Request pairing with invalid PIN
	_, err := federation.Pair(ctx, serverURL, "000000", "Attacker", "v0.0.16", "", nil)
	if err == nil {
		t.Fatal("expected invalid PIN to fail")
	}

	// 2. Push report with forged Bearer token
	forgedToken, _ := db.GenerateSecureToken()
	_, err = federation.PushReport(ctx, serverURL, forgedToken, federation.ReportPayload{
		AgentID:       "forged-uuid",
		AgentName:     "Fake Agent",
		AgentVersion:  "v0.0.16",
		SchemaVersion: 1,
		Hosts:         []db.Host{{IP: "10.0.0.1", Status: "up"}},
	})
	if err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("expected 401 Unauthorized for forged token, got: %v", err)
	}

	// 3. Pairing PIN expiration
	pinObj, _ := serverDB.CreatePairingPIN("期限切れテスト")
	// Manually set expiration to the past
	_, _ = serverDB.Exec("UPDATE federation_pairing_pins SET expires_at = datetime('now', '-1 minute') WHERE pin = ?", pinObj.PIN)

	_, errExp := federation.Pair(ctx, serverURL, pinObj.PIN, "Agent", "v0.0.16", "", nil)
	if errExp == nil || (!strings.Contains(errExp.Error(), "expired") && !strings.Contains(errExp.Error(), "400")) {
		t.Fatalf("expected expiration error, got: %v", errExp)
	}
}
