package monitor

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"lanmap/internal/db"
	"lanmap/internal/notifier"
)

func TestBroadcastMonitorThresholdAndAlert(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_broadcast.db")
	database, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("Open DB failed: %v", err)
	}
	defer database.Close()

	notif := notifier.NewNotifier(database)
	bm := NewBroadcastMonitor(database, notif)

	// Create test host
	_ = database.CreateManualHost(&db.Host{
		IP:         "192.168.1.50",
		Hostname:   "test-host",
		IsApproved: true,
	})

	// 1. Record under threshold
	for i := 0; i < 50; i++ {
		bm.RecordPacket("192.168.1.50")
	}

	if count := bm.Get1mCount("192.168.1.50"); count != 50 {
		t.Errorf("expected 50 packets, got %d", count)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	bm.evaluateStats(ctx)

	h, _ := database.GetHost("192.168.1.50")
	if h.IsStorming {
		t.Errorf("expected host not storming at 50 pkts, got true")
	}

	// 2. Exceed storm threshold (120+)
	for i := 0; i < 80; i++ {
		bm.RecordPacket("192.168.1.50")
	}

	bm.evaluateStats(ctx)

	h2, _ := database.GetHost("192.168.1.50")
	if !h2.IsStorming {
		t.Errorf("expected host storming at 130 pkts, got false")
	}
	if h2.BroadcastCount1m < 120 {
		t.Errorf("expected count >= 120, got %d", h2.BroadcastCount1m)
	}
}
