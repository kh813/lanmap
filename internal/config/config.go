package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Config represents application configuration
type Config struct {
	HTTPPort        int
	ScanInterval    time.Duration
	ScanConcurrency int
	DataDir         string
	DBPath          string
	CertsDir        string
	DefaultCertPath string
	DefaultKeyPath  string
	LogLevel        string
}

// Default settings (DefaultScanIntervalMin is 2 minutes: safe, responsive, negligible network load)
const (
	DefaultPort            = 3002
	DefaultScanIntervalMin = 2
	DefaultScanConcurrency = 30
	DefaultLogLevel        = "INFO"
)

// ResolveDataDir determines the base data directory
func ResolveDataDir() (string, error) {
	if envDir := os.Getenv("LANMAP_DATA_DIR"); envDir != "" {
		absDir, err := filepath.Abs(envDir)
		if err != nil {
			return "", fmt.Errorf("invalid LANMAP_DATA_DIR: %w", err)
		}
		return absDir, nil
	}

	execPath, err := os.Executable()
	if err != nil {
		cwd, err := os.Getwd()
		if err != nil {
			return ".", nil
		}
		return cwd, nil
	}

	execDir := filepath.Dir(execPath)
	if strings.Contains(execDir, "go-build") || strings.Contains(execDir, "/var/folders/") || strings.Contains(execDir, "\\Temp\\") {
		cwd, err := os.Getwd()
		if err == nil {
			return cwd, nil
		}
	}

	return execDir, nil
}

// LoadConfig loads configuration from environment variables with defaults
func LoadConfig() (*Config, error) {
	dataDir, err := ResolveDataDir()
	if err != nil {
		return nil, err
	}

	certsDir := filepath.Join(dataDir, "certs")
	if err := os.MkdirAll(certsDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create data directories: %w", err)
	}

	port := DefaultPort
	if pStr := os.Getenv("LANMAP_PORT"); pStr != "" {
		if p, err := strconv.Atoi(pStr); err == nil && p > 0 && p <= 65535 {
			port = p
		}
	}

	scanIntervalMin := DefaultScanIntervalMin
	if sStr := os.Getenv("LANMAP_SCAN_INTERVAL_MINUTES"); sStr != "" {
		if s, err := strconv.Atoi(sStr); err == nil && s > 0 {
			scanIntervalMin = s
		}
	}

	scanConcurrency := DefaultScanConcurrency
	if cStr := os.Getenv("LANMAP_SCAN_CONCURRENCY"); cStr != "" {
		if c, err := strconv.Atoi(cStr); err == nil && c > 0 {
			scanConcurrency = c
		}
	}

	logLevel := DefaultLogLevel
	if lStr := os.Getenv("LANMAP_LOG_LEVEL"); lStr != "" {
		logLevel = strings.ToUpper(strings.TrimSpace(lStr))
	}

	cfg := &Config{
		HTTPPort:        port,
		ScanInterval:    time.Duration(scanIntervalMin) * time.Minute,
		ScanConcurrency: scanConcurrency,
		DataDir:         dataDir,
		DBPath:          filepath.Join(dataDir, "lanmap.db"),
		CertsDir:        certsDir,
		DefaultCertPath: filepath.Join(certsDir, "cert.pem"),
		DefaultKeyPath:  filepath.Join(certsDir, "key.pem"),
		LogLevel:        logLevel,
	}

	return cfg, nil
}
