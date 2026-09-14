package db

import (
	"path/filepath"
	"testing"
)

func TestWhitelistImportAndMatching(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_whitelist.db")
	database, err := Open(dbPath)
	if err != nil {
		t.Fatalf("Open DB failed: %v", err)
	}
	defer database.Close()

	// 1. Test CSV Import
	csvContent := `
hostname,mac_address,serial_number,device_name,note
pc-takahashi,,C02XYZ123,高橋MacBook Pro,開発部
,00:11:22:33:44:55,SN98765,検証用サーバー,インフラ課
mbpm1m.parkside.tokyo,,C02M1MAX,管理者Mac,情報システム
`
	imported, err := database.ImportWhitelistCSV(csvContent)
	if err != nil {
		t.Fatalf("ImportWhitelistCSV failed: %v", err)
	}
	if imported != 3 {
		t.Errorf("expected 3 entries imported, got %d", imported)
	}

	// 2. Test Match By Hostname (exact & prefix match)
	match1, ok := database.MatchWhitelist("pc-takahashi.lan", "")
	if !ok || match1.DeviceName != "高橋MacBook Pro" {
		t.Errorf("expected match for pc-takahashi.lan, got %+v, ok=%v", match1, ok)
	}

	// 3. Test Match By MAC
	match2, ok := database.MatchWhitelist("random-hostname", "00:11:22:33:44:55")
	if !ok || match2.DeviceName != "検証用サーバー" {
		t.Errorf("expected match for MAC, got %+v, ok=%v", match2, ok)
	}

	// 4. Test Unmatched
	_, ok = database.MatchWhitelist("unknown-laptop", "aa:bb:cc:dd:ee:ff")
	if ok {
		t.Error("expected no match for unknown device")
	}

	// 5. Test ReconcileHostsWithWhitelist
	_ = database.CreateManualHost(&Host{
		IP:         "192.168.1.100",
		Hostname:   "pc-takahashi.lan",
		IsApproved: false,
	})
	_ = database.CreateManualHost(&Host{
		IP:         "192.168.1.101",
		Hostname:   "rogue-device",
		IsApproved: false,
	})

	reconciled, err := database.ReconcileHostsWithWhitelist()
	if err != nil {
		t.Fatalf("ReconcileHostsWithWhitelist failed: %v", err)
	}
	if reconciled != 1 {
		t.Errorf("expected 1 host reconciled, got %d", reconciled)
	}

	h1, _ := database.GetHost("192.168.1.100")
	if !h1.IsApproved || h1.DisplayName != "高橋MacBook Pro" {
		t.Errorf("expected host 1 to be approved with display name, got %+v", h1)
	}

	h2, _ := database.GetHost("192.168.1.101")
	if h2.IsApproved {
		t.Errorf("expected rogue host 2 to remain unapproved, got %+v", h2)
	}

	// 6. Test CSV Import with user_name column (6 columns)
	csvWithUser := `
hostname,mac_address,serial_number,device_name,user_name,note
pc-suzuki,00:aa:bb:cc:dd:ee,SN111,鈴木ThinkPad,鈴木 一郎,営業部
`
	imp2, err := database.ImportWhitelistCSV(csvWithUser)
	if err != nil || imp2 != 1 {
		t.Fatalf("ImportWhitelistCSV with user failed: %v (imported=%d)", err, imp2)
	}
	match3, ok := database.MatchWhitelist("pc-suzuki", "00:aa:bb:cc:dd:ee")
	if !ok || match3.UserName != "鈴木 一郎" {
		t.Errorf("expected match with user_name='鈴木 一郎', got %+v", match3)
	}

	_ = database.CreateManualHost(&Host{
		IP:         "192.168.1.102",
		Hostname:   "pc-suzuki",
		MACAddress: "00:aa:bb:cc:dd:ee",
		IsApproved: false,
	})
	_, _ = database.ReconcileHostsWithWhitelist()
	h3, _ := database.GetHost("192.168.1.102")
	if h3 == nil || h3.UserName != "鈴木 一郎" {
		t.Errorf("expected host 3 to have UserName='鈴木 一郎', got %+v", h3)
	}
}
