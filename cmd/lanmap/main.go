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
	"syscall"
	"time"

	"lanmap/internal/config"
	"lanmap/internal/db"
	"lanmap/internal/kuma"
	"lanmap/internal/monitor"
	"lanmap/internal/notifier"
	"lanmap/internal/scanner"
	"lanmap/internal/service"
	"lanmap/internal/web"
)

var Version = "v0.0.1"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "-v", "--version":
			fmt.Printf("lanmap (lmap) %s\n", Version)
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

func printHelp() {
	fmt.Printf(`lanmap (lmap) - LAN Host Manager & Security Detector %s

USAGE:
  lanmap                     Start lanmap server in foreground (default)
  lanmap service <command>   Manage background service (install, start, stop, etc.)
  lanmap version             Show version information
  lanmap help                Show this help message

SERVICE COMMANDS:
  install     Install service into system (systemd / launchd / Windows SCM)
  uninstall   Uninstall service from system
  start       Start background service
  stop        Stop background service
  restart     Restart background service
  status      Show current service status

ENVIRONMENT VARIABLES:
  LANMAP_DATA_DIR              Data directory path (default: same as binary)
  LANMAP_PORT                  HTTPS Port (default: 3002)
  LANMAP_SCAN_INTERVAL_MINUTES Scan interval minutes (default: 10)
  LANMAP_SCAN_CONCURRENCY      Parallel ping concurrency (default: 20)
  LANMAP_LOG_LEVEL             Log level (DEBUG/INFO/WARN/ERROR)
`, Version)
}

func runServer() {
	log.Printf("[INFO] Starting lanmap %s...", Version)

	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("[FATAL] Failed to load configuration: %v", err)
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
	km := kuma.NewManager(database)
	defer km.Close()

	webHandler, err := web.NewHandler(database, cfg, sc, notif, km)
	if err != nil {
		log.Fatalf("[FATAL] Failed to initialize web handlers: %v", err)
	}

	router := web.NewRouter(webHandler)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Initial Kuma connection & sync
	go func() {
		if err := km.Connect(ctx); err == nil {
			_, _ = km.Sync(ctx)
		}
	}()

	bm := monitor.NewBroadcastMonitor(database, notif)
	bm.Start(ctx)

	// Background Periodic Scanner & Retention Cleanup Task
	go runBackgroundTasks(ctx, cfg, database, sc, notif, km)

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

func runBackgroundTasks(ctx context.Context, cfg *config.Config, database *db.DB, sc *scanner.Scanner, notif *notifier.Notifier, km *kuma.Manager) {
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
		executeScanCycle(ctx, database, sc, notif, km)
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-scanTicker.C:
			executeScanCycle(ctx, database, sc, notif, km)
		case <-cleanupTicker.C:
			days, _ := database.GetRetentionDays()
			if deleted, err := database.CleanupOldHosts(days); err == nil && deleted > 0 {
				log.Printf("[INFO] Cleanup: removed %d expired hosts", deleted)
			}
		}
	}
}

func executeScanCycle(ctx context.Context, database *db.DB, sc *scanner.Scanner, notif *notifier.Notifier, km *kuma.Manager) {
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

	_ = km.Connect(ctx)
	_, _ = km.Sync(ctx)
}
