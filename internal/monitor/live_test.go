package monitor

import (
	"context"
	"path/filepath"
	"testing"

	"lanmap/internal/db"
	"lanmap/internal/notifier"
	"lanmap/internal/scanner"
)

func TestLiveEnvironmentAudit(t *testing.T) {
	// Look for live lanmap.db in workspace root
	dbPath := filepath.Join("..", "..", "lanmap.db")
	database, err := db.Open(dbPath)
	if err != nil {
		t.Skipf("lanmap.db not accessible: %v", err)
		return
	}
	defer database.Close()

	notif := notifier.NewNotifier(database)
	m := NewIPv6Monitor(database, notif)
	ctx := context.Background()

	t.Log("=== 1. システム近隣キャッシュ (NDP) の取得 ===")
	entries, err := scanner.GetIPv6Neighbors("")
	if err != nil {
		t.Fatalf("GetIPv6Neighbors failed: %v", err)
	}

	routerCount := 0
	for _, e := range entries {
		if e.IsRouter {
			routerCount++
			t.Logf("Router entry: IP=%s, MAC=%s, IF=%s", e.IP, e.MAC, e.Interface)
		}
	}
	t.Logf("Total routers detected in NDP table: %d", routerCount)

	t.Log("=== 2. 自ホストMACアドレスの確認 ===")
	localMACs := scanner.GetLocalMACAddresses()
	for mac := range localMACs {
		t.Logf("Local host MAC: %s", mac)
	}

	t.Log("=== 3. AuditRogueRouters の実行 ===")
	m.AuditRogueRouters(ctx)

	t.Log("=== 4. アラートマップの検証 ===")
	t.Logf("Rogue RA Alerts: %d", len(m.rogueAlerts))
	for mac, tme := range m.rogueAlerts {
		t.Logf("  🚨 ROGUE RA ALERT: MAC=%s (Time=%s)", mac, tme)
	}
	t.Logf("VLAN Notices: %d", len(m.vlanAlerts))
	for key, tme := range m.vlanAlerts {
		t.Logf("  ⚠️ VLAN NOTICE: Key=%s (Time=%s)", key, tme)
	}

	// Verify that self MAC is NEVER in rogueAlerts
	for mac := range localMACs {
		if _, ok := m.rogueAlerts[mac]; ok {
			t.Errorf("Self MAC %s was flagged as rogue router!", mac)
		}
	}

	// Verify that approved router in lanmap.db is NOT in rogueAlerts
	for _, e := range entries {
		if !e.IsRouter {
			continue
		}
		normMAC := scanner.NormalizeMAC(e.MAC)
		if h, err := database.GetHostByMAC(normMAC); err == nil && h != nil {
			if h.IsApproved || h.IsProtected {
				if _, ok := m.rogueAlerts[normMAC]; ok {
					t.Errorf("Approved router %s (%s) was flagged as rogue router!", h.Hostname, normMAC)
				}
			}
		}
	}
}
