package db

import (
	"path/filepath"
	"testing"
)

func setupTestFederationDB(t *testing.T) *DB {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test_federation.db")
	database, err := Open(dbPath)
	if err != nil {
		t.Fatalf("failed to open test db: %v", err)
	}
	t.Cleanup(func() { database.Close() })
	return database
}

func TestFederationPairingFlow(t *testing.T) {
	database := setupTestFederationDB(t)

	// 1. Create Pairing PIN
	pinObj, err := database.CreatePairingPIN("大阪支社")
	if err != nil {
		t.Fatalf("CreatePairingPIN failed: %v", err)
	}
	if len(pinObj.PIN) != 6 {
		t.Fatalf("expected 6-digit PIN, got %s", pinObj.PIN)
	}
	if pinObj.Status != "issued" {
		t.Fatalf("expected status 'issued', got %s", pinObj.Status)
	}

	// Check polling before request
	status, tok, err := database.GetPairingStatus(pinObj.PIN, "")
	if err != nil {
		t.Fatalf("GetPairingStatus failed: %v", err)
	}
	if status != "issued" || tok != "" {
		t.Fatalf("expected status 'issued' and empty token, got %s, %s", status, tok)
	}

	// 2. Request Pairing from Agent
	agentID, err := database.RequestPairing(pinObj.PIN, "大阪支社", "v0.0.16", "192.168.10.0/24", "100.64.0.5")
	if err != nil {
		t.Fatalf("RequestPairing failed: %v", err)
	}
	if agentID == "" {
		t.Fatal("expected non-empty agentID")
	}

	// Check pending requests
	pending, err := database.ListPendingPairingRequests()
	if err != nil {
		t.Fatalf("ListPendingPairingRequests failed: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending request, got %d", len(pending))
	}
	if pending[0].AgentID != agentID || pending[0].AgentName != "大阪支社" {
		t.Fatalf("unexpected pending info: %+v", pending[0])
	}

	// Check polling while requested
	status, tok, err = database.GetPairingStatus(pinObj.PIN, agentID)
	if err != nil {
		t.Fatalf("GetPairingStatus failed: %v", err)
	}
	if status != "requested" || tok != "" {
		t.Fatalf("expected status 'requested', got %s", status)
	}

	// 3. Admin Approves Pairing
	token, err := database.ApprovePairing(pinObj.PIN)
	if err != nil {
		t.Fatalf("ApprovePairing failed: %v", err)
	}
	if token == "" {
		t.Fatal("expected non-empty token from ApprovePairing")
	}

	// Check polling after approved
	status, tok, err = database.GetPairingStatus(pinObj.PIN, agentID)
	if err != nil {
		t.Fatalf("GetPairingStatus after approval failed: %v", err)
	}
	if status != "approved" || tok != token {
		t.Fatalf("expected status 'approved' and token %s, got %s, %s", token, status, tok)
	}

	// 4. Verify Agent in DB
	agent, err := database.GetAgentByID(agentID)
	if err != nil {
		t.Fatalf("GetAgentByID failed: %v", err)
	}
	if agent == nil || agent.Name != "大阪支社" || agent.Status != "active" {
		t.Fatalf("unexpected agent: %+v", agent)
	}

	// Verify Token Authentication
	tokenHash := HashToken(token)
	authAgent, err := database.GetAgentByTokenHash(tokenHash)
	if err != nil {
		t.Fatalf("GetAgentByTokenHash failed: %v", err)
	}
	if authAgent == nil || authAgent.ID != agentID {
		t.Fatalf("token auth failed, expected agent %s, got %+v", agentID, authAgent)
	}

	// 5. Test Revoke
	if err := database.RevokeAgent(agentID); err != nil {
		t.Fatalf("RevokeAgent failed: %v", err)
	}
	revokedAgent, err := database.GetAgentByTokenHash(tokenHash)
	if err != nil {
		t.Fatalf("GetAgentByTokenHash after revoke error: %v", err)
	}
	if revokedAgent != nil {
		t.Fatalf("expected nil after revoke, got %+v", revokedAgent)
	}
}

func TestFederationHostIsolation(t *testing.T) {
	database := setupTestFederationDB(t)

	// Register 2 agents
	pin1, _ := database.CreatePairingPIN("大阪支社")
	agent1ID, _ := database.RequestPairing(pin1.PIN, "大阪支社", "v0.0.16", "192.168.1.0/24", "100.64.0.5")
	_, _ = database.ApprovePairing(pin1.PIN)

	pin2, _ := database.CreatePairingPIN("名古屋支社")
	agent2ID, _ := database.RequestPairing(pin2.PIN, "名古屋支社", "v0.0.16", "192.168.1.0/24", "100.64.0.6")
	_, _ = database.ApprovePairing(pin2.PIN)

	// 1. Insert Local Server Host on 192.168.1.50
	rtt := 1.5
	localHost := &Host{
		IP:          "192.168.1.50",
		MACAddress:  "00:11:22:33:44:55",
		Hostname:    "tokyo-server",
		DisplayName: "本社サーバー",
		Status:      "up",
		PingRTTMs:   &rtt,
	}
	_, _, err := database.UpsertHostOnScan(localHost)
	if err != nil {
		t.Fatalf("UpsertHostOnScan local failed: %v", err)
	}

	// 2. Upsert Remote Hosts from Agent 1 with the SAME IP (192.168.1.50)
	agent1Hosts := []Host{
		{
			IP:          "192.168.1.50",
			MACAddress:  "aa:bb:cc:dd:ee:01",
			Hostname:    "osaka-printer",
			DisplayName: "大阪プリンター",
			Status:      "up",
			PingRTTMs:   &rtt,
		},
		{
			IP:          "192.168.1.51",
			MACAddress:  "aa:bb:cc:dd:ee:02",
			Hostname:    "osaka-pc",
			DisplayName: "大阪PC",
			Status:      "up",
			PingRTTMs:   &rtt,
		},
	}
	if err := database.UpsertRemoteHosts(agent1ID, agent1Hosts); err != nil {
		t.Fatalf("UpsertRemoteHosts agent1 failed: %v", err)
	}

	// 3. Upsert Remote Hosts from Agent 2 also with the SAME IP (192.168.1.50)
	agent2Hosts := []Host{
		{
			IP:          "192.168.1.50",
			MACAddress:  "11:22:33:44:55:66",
			Hostname:    "nagoya-nas",
			DisplayName: "名古屋NAS",
			Status:      "up",
			PingRTTMs:   &rtt,
		},
	}
	if err := database.UpsertRemoteHosts(agent2ID, agent2Hosts); err != nil {
		t.Fatalf("UpsertRemoteHosts agent2 failed: %v", err)
	}

	// Verify Isolation:
	// Local server only (agentID == nil)
	localList, err := database.ListHostsFilteredWithAgent(nil, "all", 0, nil)
	if err != nil {
		t.Fatalf("ListHostsFilteredWithAgent local failed: %v", err)
	}
	if len(localList) != 1 {
		t.Fatalf("expected 1 local host, got %d", len(localList))
	}
	if localList[0].Hostname != "tokyo-server" || localList[0].AgentID != nil {
		t.Fatalf("unexpected local host: %+v", localList[0])
	}

	// Osaka Agent only
	osakaList, err := database.ListHostsFilteredWithAgent(nil, "all", 0, &agent1ID)
	if err != nil {
		t.Fatalf("ListHostsFilteredWithAgent osaka failed: %v", err)
	}
	if len(osakaList) != 2 {
		t.Fatalf("expected 2 osaka hosts, got %d", len(osakaList))
	}
	if osakaList[0].AgentName != "大阪支社" || *osakaList[0].AgentID != agent1ID {
		t.Fatalf("unexpected osaka host agent info: %+v", osakaList[0])
	}

	// Nagoya Agent only
	nagoyaList, err := database.ListHostsFilteredWithAgent(nil, "all", 0, &agent2ID)
	if err != nil {
		t.Fatalf("ListHostsFilteredWithAgent nagoya failed: %v", err)
	}
	if len(nagoyaList) != 1 {
		t.Fatalf("expected 1 nagoya host, got %d", len(nagoyaList))
	}
	if nagoyaList[0].Hostname != "nagoya-nas" || nagoyaList[0].AgentName != "名古屋支社" {
		t.Fatalf("unexpected nagoya host: %+v", nagoyaList[0])
	}

	// All hosts (*)
	allStr := "*"
	allList, err := database.ListHostsFilteredWithAgent(nil, "all", 0, &allStr)
	if err != nil {
		t.Fatalf("ListHostsFilteredWithAgent all failed: %v", err)
	}
	if len(allList) != 4 {
		t.Fatalf("expected 4 total hosts, got %d", len(allList))
	}

	// Test Agent Deletion cascades to remote hosts
	if err := database.DeleteAgent(agent2ID); err != nil {
		t.Fatalf("DeleteAgent failed: %v", err)
	}
	allAfterDelete, _ := database.ListHostsFilteredWithAgent(nil, "all", 0, &allStr)
	if len(allAfterDelete) != 3 {
		t.Fatalf("expected 3 hosts after deleting nagoya agent, got %d", len(allAfterDelete))
	}
}
