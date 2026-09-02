package kuma

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/breml/go-uptime-kuma-client/monitor"
	"lanmap/internal/db"
)

type mockKumaAPI struct {
	monitors   map[int64]monitor.Base
	pingMonMap map[int64]*monitor.Ping
	nextID     int64
}

func newMockKumaAPI() *mockKumaAPI {
	return &mockKumaAPI{
		monitors:   make(map[int64]monitor.Base),
		pingMonMap: make(map[int64]*monitor.Ping),
		nextID:     100,
	}
}

func (m *mockKumaAPI) addPing(name, ip string, active bool) int64 {
	m.nextID++
	id := m.nextID
	b := monitor.Base{ID: id, Name: name, IsActive: active}
	p := &monitor.Ping{
		Base:        b,
		PingDetails: monitor.PingDetails{Hostname: ip},
	}
	m.monitors[id] = b
	m.pingMonMap[id] = p
	return id
}

func (m *mockKumaAPI) GetMonitors(ctx context.Context) ([]monitor.Base, error) {
	var list []monitor.Base
	for _, b := range m.monitors {
		list = append(list, b)
	}
	return list, nil
}

func (m *mockKumaAPI) GetMonitorAs(ctx context.Context, id int64, target any) error {
	if p, ok := m.pingMonMap[id]; ok {
		if t, ok := target.(*monitor.Ping); ok {
			*t = *p
			return nil
		}
	}
	return nil
}

func (m *mockKumaAPI) CreateMonitor(ctx context.Context, mon monitor.Monitor) (int64, error) {
	m.nextID++
	id := m.nextID
	if p, ok := mon.(*monitor.Ping); ok {
		p.ID = id
		m.monitors[id] = p.Base
		m.pingMonMap[id] = p
	}
	return id, nil
}

func (m *mockKumaAPI) UpdateMonitor(ctx context.Context, mon monitor.Monitor) error {
	if p, ok := mon.(*monitor.Ping); ok {
		m.monitors[p.ID] = p.Base
		m.pingMonMap[p.ID] = p
	}
	return nil
}

func (m *mockKumaAPI) PauseMonitor(ctx context.Context, id int64) error {
	if b, ok := m.monitors[id]; ok {
		b.IsActive = false
		m.monitors[id] = b
	}
	return nil
}

func (m *mockKumaAPI) ResumeMonitor(ctx context.Context, id int64) error {
	if b, ok := m.monitors[id]; ok {
		b.IsActive = true
		m.monitors[id] = b
	}
	return nil
}

func (m *mockKumaAPI) DeleteMonitor(ctx context.Context, id int64) error {
	delete(m.monitors, id)
	delete(m.pingMonMap, id)
	return nil
}

func (m *mockKumaAPI) Disconnect() error {
	return nil
}

func TestKumaSyncReconciliation(t *testing.T) {
	tempDir := t.TempDir()
	dbPath := filepath.Join(tempDir, "test_kuma.db")
	database, err := db.Open(dbPath)
	if err != nil {
		t.Fatalf("db.Open failed: %v", err)
	}
	defer database.Close()

	mgr := NewManager(database)
	mockAPI := newMockKumaAPI()
	mgr.SetAPI(mockAPI)

	// Setup lanmap hosts
	// Host 1: Match (Pattern A)
	_ = database.CreateManualHost(&db.Host{IP: "192.168.1.10", DisplayName: "Router", Hostname: "router.lan"})
	mockAPI.addPing("Router", "192.168.1.10", true)

	// Host 2: Conflict (Pattern B)
	_ = database.CreateManualHost(&db.Host{IP: "192.168.1.20", DisplayName: "Main Server", Hostname: "server1"})
	mockAPI.addPing("File Storage Svr", "192.168.1.20", true)

	// Host 3: Exists only in Kuma (Pattern C)
	mockAPI.addPing("External Switch", "192.168.1.30", true)

	// Host 4: Had Kuma ID in lanmap, but deleted in Kuma (Pattern D)
	oldKumaID := int64(999)
	_ = database.CreateManualHost(&db.Host{IP: "192.168.1.40", DisplayName: "Old Device", UptimeKumaID: &oldKumaID, IsMonitored: true})

	ctx := context.Background()
	res, err := mgr.Sync(ctx)
	if err != nil {
		t.Fatalf("Sync failed: %v", err)
	}

	if res.PatternACount != 1 {
		t.Errorf("expected 1 Pattern A, got %d", res.PatternACount)
	}
	if res.PatternBCount != 1 {
		t.Errorf("expected 1 Pattern B, got %d", res.PatternBCount)
	}
	if res.PatternCCount != 1 {
		t.Errorf("expected 1 Pattern C, got %d", res.PatternCCount)
	}
	if res.PatternDCount != 1 {
		t.Errorf("expected 1 Pattern D, got %d", res.PatternDCount)
	}

	// Verify Host 1
	h1, _ := database.GetHost("192.168.1.10")
	if !h1.IsMonitored || h1.HasConflict || h1.UptimeKumaID == nil {
		t.Errorf("unexpected Host 1 state: %+v", h1)
	}

	// Verify Host 2 (Conflict)
	h2, _ := database.GetHost("192.168.1.20")
	if !h2.HasConflict || h2.KumaName != "File Storage Svr" {
		t.Errorf("unexpected Host 2 state: %+v", h2)
	}

	// Resolve conflict for Host 2 (Adopt Kuma name)
	err = mgr.ResolveConflict(ctx, "192.168.1.20", false)
	if err != nil {
		t.Fatalf("ResolveConflict failed: %v", err)
	}
	h2Resolved, _ := database.GetHost("192.168.1.20")
	if h2Resolved.HasConflict || h2Resolved.DisplayName != "File Storage Svr" {
		t.Errorf("unexpected resolved Host 2 state: %+v", h2Resolved)
	}

	// Verify Host 3 (Imported)
	h3, _ := database.GetHost("192.168.1.30")
	if h3 == nil || !h3.IsMonitored || h3.DisplayName != "External Switch" {
		t.Errorf("unexpected Host 3 state: %+v", h3)
	}

	// Verify Host 4 (Unlinked)
	h4, _ := database.GetHost("192.168.1.40")
	if h4.UptimeKumaID != nil || h4.IsMonitored {
		t.Errorf("unexpected Host 4 state: %+v", h4)
	}
}
