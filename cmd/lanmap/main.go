package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"lanmap/internal/config"
	"lanmap/internal/db"
	"lanmap/internal/monitor"
	"lanmap/internal/notifier"
	"lanmap/internal/scanner"
	"lanmap/internal/service"
	"lanmap/internal/updater"
	"lanmap/internal/web"
)

// Version is injected during build via -ldflags, defaults to development
var Version = "v0.0.13"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "-v", "--version":
			fmt.Printf("lanmap (lmap) %s\n", Version)
			return
		case "update", "upgrade":
			handleCLIUpdate()
			return
		case "service":
			if len(os.Args) < 3 {
				fmt.Println("Usage: lanmap service [install|uninstall|start|stop|restart|status]")
				os.Exit(1)
			}
			if err := service.HandleCommand(os.Args[2]); err != nil {
				log.Fatalf("[ERROR] Service command failed: %v", err)
			}
			return
		case "help", "-h", "--help":
			printHelp()
			return
		}
	}

	runServer()
}

func handleCLIUpdate() {
	fmt.Printf("🔍 Checking for updates on GitHub (current: %s)...\n", Version)
	rel, err := updater.CheckLatestRelease(Version)
	if err != nil {
		log.Fatalf("❌ Failed to check for updates: %v", err)
	}

	if !rel.IsNewer {
		fmt.Printf("✅ You are already using the latest version (%s).\n", Version)
		return
	}

	fmt.Printf("🚀 Found new release: %s (Published: %s)\n", rel.TagName, rel.PublishedAt.Format("2006-01-02 15:04"))
	if rel.AssetURL == "" {
		log.Fatalf("❌ No matching release asset found for %s/%s", runtime.GOOS, runtime.GOARCH)
	}

	fmt.Printf("⬇️  Downloading asset %s...\n", rel.AssetName)
	if err := updater.DownloadAndApplyUpdate(rel.AssetURL); err != nil {
		log.Fatalf("❌ Update failed: %v", err)
	}

	fmt.Printf("🎉 Successfully updated to %s!\n", rel.TagName)
	fmt.Println("Please restart lanmap or run 'lanmap service restart' to run the new version.")
}

func printHelp() {
	fmt.Printf(`lanmap (lmap) - LAN Host Manager & Security Detector %s

USAGE:
  lanmap                     Start lanmap server in foreground (default)
  lanmap service <command>   Manage background service (install, start, stop, etc.)
  lanmap update              Check and apply update from GitHub Releases
  lanmap version             Show version information
  lanmap help                Show this help message

SERVICE COMMANDS:
  install     Install service into system (systemd / launchd / Windows SCM)
  uninstall   Uninstall service from system
  start       Start background service
  stop        Stop background service
  restart     Restart background service
  status      Check service status

ENVIRONMENT VARIABLES:
  LANMAP_PORT                  HTTP/HTTPS server port (default: 3002)
  LANMAP_DATA_DIR              Database and certificates directory (default: binary dir)
  LANMAP_SCAN_INTERVAL_MINUTES Scan interval in minutes (default: 2)
  LANMAP_SCAN_CONCURRENCY      Max concurrent ARP/ICMP probes (default: 30)
  LANMAP_LOG_LEVEL             Log level (DEBUG/INFO/WARN/ERROR)
`, Version)
}

func runServer() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("[FATAL] Failed to load configuration: %v", err)
	}
	cfg.Version = Version

	log.Printf("[INFO] Starting lanmap %s...", Version)

	if err := os.MkdirAll(cfg.DataDir, 0755); err != nil {
		log.Fatalf("[FATAL] Failed to create data directory at %s: %v", cfg.DataDir, err)
	}

	database, err := db.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("[FATAL] Failed to initialize SQLite database at %s: %v", cfg.DBPath, err)
	}
	defer database.Close()
	log.Printf("[INFO] Database initialized at %s", cfg.DBPath)

	sc := scanner.NewScanner(database, cfg)
	_ = sc.EnsureLocalSegmentAutoRegistered()

	notif := notifier.NewNotifier(database)

	webHandler, err := web.NewHandler(database, cfg, sc, notif)
	if err != nil {
		log.Fatalf("[FATAL] Failed to initialize web handlers: %v", err)
	}

	router := web.NewRouter(webHandler)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bm := monitor.NewBroadcastMonitor(database, notif)
	bm.Start(ctx)

	dhcpMon := monitor.NewDHCPMonitor(database, notif)
	dhcpMon.Start(ctx)

	// Background Periodic Scanner & Retention Cleanup Task
	go runBackgroundTasks(ctx, cfg, database, sc, notif)

	// TLS Setup (Section 10.1)
	settings, _ := database.GetAllSettings()
	customCert := settings["tls_cert_path"]
	customKey := settings["tls_key_path"]

	cert, err := config.GetTLSKeyPair(customCert, customKey, cfg.DefaultCertPath, cfg.DefaultKeyPath)
	if err != nil {
		log.Fatalf("[FATAL] Failed to setup TLS certificates: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	addr := fmt.Sprintf(":%d", cfg.HTTPPort)
	server := &http.Server{
		Addr:         addr,
		Handler:      router,
		TLSConfig:    tlsConfig,
		ErrorLog:     log.New(&tlsLogFilter{debug: cfg.LogLevel == "DEBUG"}, "", 0),
		ReadTimeout:  15 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Server start in goroutine
	go func() {
		log.Printf("[INFO] Web UI is accessible at: https://localhost:%d", cfg.HTTPPort)
		if err := server.ListenAndServeTLS("", ""); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("[FATAL] HTTPS Server failed: %v", err)
		}
	}()

	// Graceful Shutdown on SIGINT / SIGTERM
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	sig := <-sigChan
	log.Printf("[INFO] Received signal %v. Initiating graceful shutdown...", sig)

	cancel()

	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()

	if err := server.Shutdown(shutdownCtx); err != nil {
		log.Printf("[WARN] HTTP server shutdown warning: %v", err)
	}

	log.Println("[INFO] lanmap exited cleanly.")
}

func runBackgroundTasks(ctx context.Context, cfg *config.Config, database *db.DB, sc *scanner.Scanner, notif *notifier.Notifier) {
	scanTicker := time.NewTicker(cfg.ScanInterval)
	defer scanTicker.Stop()

	cleanupTicker := time.NewTicker(6 * time.Hour)
	defer cleanupTicker.Stop()

	retDays, _ := database.GetRetentionDays()
	if deleted, err := database.CleanupOldHosts(retDays); err == nil && deleted > 0 {
		log.Printf("[INFO] Cleanup: removed %d expired hosts (retention: %d days)", deleted, retDays)
	}

	// Initial scan in background immediately
	go func() {
		time.Sleep(1 * time.Second)
		executeScanCycle(ctx, database, sc, notif)
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-scanTicker.C:
			executeScanCycle(ctx, database, sc, notif)
		case <-cleanupTicker.C:
			days, _ := database.GetRetentionDays()
			if deleted, err := database.CleanupOldHosts(days); err == nil && deleted > 0 {
				log.Printf("[INFO] Cleanup: removed %d expired hosts", deleted)
			}
		}
	}
}

func executeScanCycle(ctx context.Context, database *db.DB, sc *scanner.Scanner, notif *notifier.Notifier) {
	log.Println("[INFO] Running scheduled network scan...")
	reports, err := sc.ScanAll(ctx)
	if err != nil {
		log.Printf("[WARN] Scan cycle error: %v", err)
		return
	}

	var unapprovedAlerts []*db.Host
	for _, r := range reports {
		if r.UnapprovedAlert {
			unapprovedAlerts = append(unapprovedAlerts, r.Host)
		}
	}

	if len(unapprovedAlerts) > 0 {
		log.Printf("[WARN] 🚨 %d unapproved host(s) detected during scan! Sending alerts...", len(unapprovedAlerts))
		_ = notif.NotifyUnapprovedHosts(ctx, unapprovedAlerts)
	}
}

// tlsLogFilter filters benign TLS handshake warnings from browsers rejecting self-signed certs
type tlsLogFilter struct {
	debug bool
}

func (f *tlsLogFilter) Write(p []byte) (n int, err error) {
	msg := string(p)
	if strings.Contains(msg, "tls: unknown certificate") ||
		strings.Contains(msg, "tls: bad certificate") ||
		strings.Contains(msg, "remote error: tls:") {
		if f.debug {
			log.Printf("[DEBUG] %s", strings.TrimSpace(msg))
		}
		return len(p), nil
	}
	return os.Stderr.Write(p)
}
