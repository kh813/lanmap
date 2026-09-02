package notifier

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"lanmap/internal/db"
)

func TestPayloadFormatting(t *testing.T) {
	hosts := []*db.Host{
		{
			IP:          "192.168.1.55",
			Hostname:    "rogue-device",
			MACAddress:  "00:11:22:33:44:55",
			VendorModel: "Unknown",
			OSVendor:    "Linux",
		},
	}

	// Slack
	slack := FormatSlackPayload(hosts)
	if slack["text"] == "" || len(slack["attachments"].([]map[string]interface{})) != 1 {
		t.Errorf("unexpected Slack payload: %+v", slack)
	}

	// Discord
	discord := FormatDiscordPayload(hosts)
	if discord["content"] == "" || len(discord["embeds"].([]map[string]interface{})) != 1 {
		t.Errorf("unexpected Discord payload: %+v", discord)
	}

	// Google Chat
	gchat := FormatGoogleChatPayload(hosts)
	if gchat["text"] == "" {
		t.Errorf("unexpected Google Chat payload: %+v", gchat)
	}

	// Teams
	teams := FormatTeamsPayload(hosts)
	if teams["title"] == "" || len(teams["sections"].([]map[string]interface{})) != 1 {
		t.Errorf("unexpected Teams payload: %+v", teams)
	}
}

func TestAlertDeduplicationAndResendPolicy(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_notifier.db")
	database, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open failed: %v", err)
	}
	defer database.Close()

	n := NewNotifier(database)

	approvedHost := &db.Host{IP: "192.168.1.10", IsApproved: true, Status: "up"}
	if n.ShouldAlert(approvedHost, true, false, "") {
		t.Error("expected approved host to not trigger alert")
	}

	unapprovedHost := &db.Host{IP: "192.168.1.20", IsApproved: false, Status: "up"}

	// 1. First discovery -> alert
	if !n.ShouldAlert(unapprovedHost, true, false, "") {
		t.Error("expected first discovery to trigger alert")
	}

	// 2. Next scan while still up -> NO duplicate alert
	if n.ShouldAlert(unapprovedHost, false, false, "up") {
		t.Error("expected continuous up host to be suppressed")
	}

	// 3. Host went down, then came back up -> alert triggered
	if !n.ShouldAlert(unapprovedHost, false, false, "down") {
		t.Error("expected down->up transition to trigger alert")
	}
}

func TestWebhookDelivery(t *testing.T) {
	var slackCount int32
	var discordCount int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slack" {
			atomic.AddInt32(&slackCount, 1)
			var body map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			w.WriteHeader(http.StatusOK)
		} else if r.URL.Path == "/discord" {
			atomic.AddInt32(&discordCount, 1)
			var body map[string]interface{}
			_ = json.NewDecoder(r.Body).Decode(&body)
			w.WriteHeader(http.StatusOK)
		} else {
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_notifier_delivery.db")
	database, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open failed: %v", err)
	}
	defer database.Close()

	_ = database.SetSetting("webhook_slack_url", server.URL+"/slack")
	_ = database.SetSetting("webhook_discord_url", server.URL+"/discord")

	n := NewNotifier(database)

	hosts := []*db.Host{
		{
			IP:          "192.168.1.99",
			Hostname:    "unauthorized-laptop",
			MACAddress:  "aa:bb:cc:dd:ee:ff",
			VendorModel: "Apple",
			OSVendor:    "macOS",
			IsApproved:  false,
		},
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	err = n.NotifyUnapprovedHosts(ctx, hosts)
	if err != nil {
		t.Fatalf("NotifyUnapprovedHosts failed: %v", err)
	}

	if atomic.LoadInt32(&slackCount) != 1 {
		t.Errorf("expected 1 Slack call, got %d", slackCount)
	}
	if atomic.LoadInt32(&discordCount) != 1 {
		t.Errorf("expected 1 Discord call, got %d", discordCount)
	}
}
