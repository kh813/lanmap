package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLoadConfigDefaults(t *testing.T) {
	tempDir := t.TempDir()
	os.Setenv("LANMAP_DATA_DIR", tempDir)
	defer os.Unsetenv("LANMAP_DATA_DIR")

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.HTTPPort != DefaultPort {
		t.Errorf("expected port %d, got %d", DefaultPort, cfg.HTTPPort)
	}
	if cfg.ScanInterval != time.Duration(DefaultScanIntervalMin)*time.Minute {
		t.Errorf("expected scan interval %v, got %v", time.Duration(DefaultScanIntervalMin)*time.Minute, cfg.ScanInterval)
	}
	if cfg.ScanConcurrency != DefaultScanConcurrency {
		t.Errorf("expected concurrency %d, got %d", DefaultScanConcurrency, cfg.ScanConcurrency)
	}
	if cfg.DataDir != tempDir {
		t.Errorf("expected dataDir %s, got %s", tempDir, cfg.DataDir)
	}
	if cfg.DBPath != filepath.Join(tempDir, "lanmap.db") {
		t.Errorf("expected dbPath %s, got %s", filepath.Join(tempDir, "lanmap.db"), cfg.DBPath)
	}
}

func TestLoadConfigEnvOverrides(t *testing.T) {
	tempDir := t.TempDir()
	os.Setenv("LANMAP_DATA_DIR", tempDir)
	os.Setenv("LANMAP_PORT", "8080")
	os.Setenv("LANMAP_SCAN_INTERVAL_MINUTES", "5")
	os.Setenv("LANMAP_SCAN_CONCURRENCY", "50")
	os.Setenv("LANMAP_LOG_LEVEL", "DEBUG")
	defer func() {
		os.Unsetenv("LANMAP_DATA_DIR")
		os.Unsetenv("LANMAP_PORT")
		os.Unsetenv("LANMAP_SCAN_INTERVAL_MINUTES")
		os.Unsetenv("LANMAP_SCAN_CONCURRENCY")
		os.Unsetenv("LANMAP_LOG_LEVEL")
	}()

	cfg, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig failed: %v", err)
	}

	if cfg.HTTPPort != 8080 {
		t.Errorf("expected port 8080, got %d", cfg.HTTPPort)
	}
	if cfg.ScanInterval != 5*time.Minute {
		t.Errorf("expected scan interval 5m, got %v", cfg.ScanInterval)
	}
	if cfg.ScanConcurrency != 50 {
		t.Errorf("expected concurrency 50, got %d", cfg.ScanConcurrency)
	}
	if cfg.LogLevel != "DEBUG" {
		t.Errorf("expected logLevel DEBUG, got %s", cfg.LogLevel)
	}
}
