package kuma

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	kumaclient "github.com/breml/go-uptime-kuma-client"
	"github.com/breml/go-uptime-kuma-client/monitor"
	"lanmap/internal/db"
)

// KumaAPI abstracts the Uptime Kuma client methods used by lanmap
type KumaAPI interface {
	GetMonitors(ctx context.Context) ([]monitor.Base, error)
	GetMonitorAs(ctx context.Context, id int64, target any) error
	CreateMonitor(ctx context.Context, mon monitor.Monitor) (int64, error)
	UpdateMonitor(ctx context.Context, mon monitor.Monitor) error
	PauseMonitor(ctx context.Context, id int64) error
	ResumeMonitor(ctx context.Context, id int64) error
	DeleteMonitor(ctx context.Context, id int64) error
	Disconnect() error
}

type realKumaClient struct {
	client *kumaclient.Client
}

func (r *realKumaClient) GetMonitors(ctx context.Context) ([]monitor.Base, error) {
	return r.client.GetMonitors(ctx)
}

func (r *realKumaClient) GetMonitorAs(ctx context.Context, id int64, target any) error {
	return r.client.GetMonitorAs(ctx, id, target)
}

func (r *realKumaClient) CreateMonitor(ctx context.Context, mon monitor.Monitor) (int64, error) {
	return r.client.CreateMonitor(ctx, mon)
}

func (r *realKumaClient) UpdateMonitor(ctx context.Context, mon monitor.Monitor) error {
	return r.client.UpdateMonitor(ctx, mon)
}

func (r *realKumaClient) PauseMonitor(ctx context.Context, id int64) error {
	return r.client.PauseMonitor(ctx, id)
}

func (r *realKumaClient) ResumeMonitor(ctx context.Context, id int64) error {
	return r.client.ResumeMonitor(ctx, id)
}

func (r *realKumaClient) DeleteMonitor(ctx context.Context, id int64) error {
	return r.client.DeleteMonitor(ctx, id)
}

func (r *realKumaClient) Disconnect() error {
	return r.client.Disconnect()
}

// Manager manages Uptime Kuma connection and synchronizations
type Manager struct {
	db        *db.DB
	api       KumaAPI
	status    string
	lastError string
	mu        sync.RWMutex
}

// NewManager creates a Kuma Manager instance
func NewManager(database *db.DB) *Manager {
	return &Manager{
		db:     database,
		status: "未接続",
	}
}

// SetAPI sets custom or mock KumaAPI (used in testing or dependency injection)
func (m *Manager) SetAPI(api KumaAPI) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.api = api
	if api != nil {
		m.status = "🟢 接続中"
		m.lastError = ""
	} else {
		m.status = "未接続"
	}
}

// GetStatus returns the current connection status and error message
func (m *Manager) GetStatus() (string, string) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.status, m.lastError
}

// Connect initializes or re-establishes connection to Uptime Kuma
func (m *Manager) Connect(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	settings, err := m.db.GetAllSettings()
	if err != nil {
		return err
	}

	baseURL := strings.TrimSpace(settings["kuma_url"])
	if baseURL == "" {
		m.status = "未設定"
		m.lastError = ""
		if m.api != nil {
			_ = m.api.Disconnect()
			m.api = nil
		}
		return nil
	}

	username := strings.TrimSpace(settings["kuma_username"])
	password := settings["kuma_password"]

	// Create real kuma client
	client, err := kumaclient.New(ctx, baseURL, username, password, kumaclient.WithConnectTimeout(10*time.Second))
	if err != nil {
		m.status = "🔴 接続・認証エラー"
		m.lastError = err.Error()
		log.Printf("[WARN] Kuma: connection failed to %s: %v", baseURL, err)
		return fmt.Errorf("kuma connection failed: %w", err)
	}

	if m.api != nil {
		_ = m.api.Disconnect()
	}

	m.api = &realKumaClient{client: client}
	m.status = "🟢 接続中"
	m.lastError = ""
	return nil
}

// Close disconnects Kuma API client
func (m *Manager) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.api != nil {
		err := m.api.Disconnect()
		m.api = nil
		m.status = "未接続"
		return err
	}
	return nil
}
