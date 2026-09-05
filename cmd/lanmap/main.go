package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
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
	"lanmap/internal/federation"
	"lanmap/internal/monitor"
	"lanmap/internal/notifier"
	"lanmap/internal/scanner"
	"lanmap/internal/service"
	"lanmap/internal/updater"
	"lanmap/internal/web"
)

// Version can be overwritten at build time with -ldflags
var Version = "v0.0.18"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "-v", "--version":
			fmt.Printf("lanmap (lmap) %s\n", Version)
			return
		case "update", "upgrade":
			handleCLIUpdate()
			return
		case "agent":
			handleCLIAgent()
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
  lanmap agent <command>     Federation remote agent commands (pair, status, unpair, report)
  lanmap service <command>   Manage background service (install, start, stop, etc.)
  lanmap update              Check and apply update from GitHub Releases
  lanmap version             Show version information
  lanmap help                Show this help message

AGENT COMMANDS (Federation):
  pair      Pair this node as an agent to a central lanmap server
            Flags: --server <URL> --pin <PIN> [--name <Name>] [--cidr <CIDR>]
  status    Show current federation agent pairing status
  unpair    Remove federation pairing from this node
  report    Immediately push local network inventory to central server

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

	agentCfg, _ := federation.LoadAgentConfig(database)
	if agentCfg.IsPaired() {
		log.Printf("[INFO] 🌐 Federation Agent active: paired with %s (Site: %s, ID: %s)", agentCfg.ServerURL, agentCfg.AgentName, agentCfg.AgentID)
	}

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

	// Automatically push network report to central federation server if paired
	pushFederationReportIfPaired(ctx, database)
}

func pushFederationReportIfPaired(ctx context.Context, database *db.DB) {
	agentCfg, err := federation.LoadAgentConfig(database)
	if err != nil || !agentCfg.IsPaired() {
		return
	}

	hosts, err := database.ListHostsFilteredWithAgent(nil, "all", 0, nil)
	if err != nil {
		log.Printf("[WARN] [Federation] Failed to list hosts for report: %v", err)
		return
	}

	var hostList []db.Host
	for _, h := range hosts {
		if h != nil {
			hostList = append(hostList, *h)
		}
	}

	payload := federation.ReportPayload{
		AgentID:       agentCfg.AgentID,
		AgentName:     agentCfg.AgentName,
		AgentVersion:  Version,
		SchemaVersion: federation.CurrentSchemaVersion,
		ReportedAt:    time.Now(),
		Hosts:         hostList,
	}

	resp, err := federation.PushReport(ctx, agentCfg.ServerURL, agentCfg.Token, payload)
	if err != nil {
		log.Printf("[WARN] [Federation] Failed to push report to %s: %v", agentCfg.ServerURL, err)
		return
	}

	if resp.VersionMismatch {
		log.Printf("[WARN] [Federation] ⚠️ Version mismatch reported by server: %s", resp.Message)
	} else {
		log.Printf("[INFO] [Federation] ✅ %s", resp.Message)
	}
}

func handleCLIAgent() {
	if len(os.Args) < 3 {
		printAgentHelp()
		os.Exit(1)
	}

	switch os.Args[2] {
	case "pair":
		fs := flag.NewFlagSet("pair", flag.ExitOnError)
		serverURL := fs.String("server", "", "URL of central lanmap server (e.g. http://100.64.0.1:3002)")
		pin := fs.String("pin", "", "6-digit pairing PIN issued by server")
		name := fs.String("name", "", "Display name of this remote site (e.g. '大阪支社')")
		cidr := fs.String("cidr", "", "Monitored local CIDR (optional)")
		_ = fs.Parse(os.Args[3:])

		if *serverURL == "" || *pin == "" {
			fmt.Println("❌ Error: --server and --pin are required.")
			fs.Usage()
			os.Exit(1)
		}
		handleAgentPair(*serverURL, *pin, *name, *cidr)
	case "status":
		handleAgentStatus()
	case "unpair":
		handleAgentUnpair()
	case "report":
		handleAgentReport()
	default:
		printAgentHelp()
		os.Exit(1)
	}
}

func printAgentHelp() {
	fmt.Printf(`lanmap agent - Federation Remote Agent Management

USAGE:
  lanmap agent pair --server <URL> --pin <PIN> [--name <Name>] [--cidr <CIDR>]
  lanmap agent status
  lanmap agent unpair
  lanmap agent report

COMMANDS:
  pair      Pair this node as an agent with the central lanmap server
  status    Display current pairing and synchronization status
  unpair    Remove pairing information and stop reporting
  report    Immediately push local inventory to central server
`)
}

func handleAgentPair(serverURL, pin, name, cidr string) {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("❌ Failed to load configuration: %v", err)
	}

	database, err := db.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("❌ Failed to open database at %s: %v", cfg.DBPath, err)
	}
	defer database.Close()

	if name == "" {
		hname, _ := os.Hostname()
		if hname != "" {
			name = hname
		} else {
			name = "Remote Site"
		}
	}

	if cidr == "" {
		nets, _ := scanner.DetectLocalNetworks()
		if len(nets) > 0 {
			cidr = nets[0].CIDR
		}
	}

	fmt.Printf("🔗 Requesting pairing with central server: %s\n", serverURL)
	fmt.Printf("   Site Name: %s\n", name)
	if cidr != "" {
		fmt.Printf("   Local CIDR: %s\n", cidr)
	}
	fmt.Printf("   PIN: %s\n", pin)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	agentCfg, err := federation.Pair(ctx, serverURL, pin, name, Version, cidr, func(agentID string) {
		fmt.Printf("\n⏳ Pairing request sent (Agent ID: %s).\n", agentID)
		fmt.Println("👉 Please open the central server's Web UI and click 'Approve' on the pending request.")
		fmt.Println("   Waiting for approval (up to 3 minutes)...")
	})
	if err != nil {
		log.Fatalf("❌ Pairing failed: %v", err)
	}

	if err := federation.SaveAgentConfig(database, agentCfg); err != nil {
		log.Fatalf("❌ Failed to save agent configuration: %v", err)
	}

	fmt.Println("\n🎉 Successfully paired with central server!")
	fmt.Printf("   Agent ID:  %s\n", agentCfg.AgentID)
	fmt.Printf("   Site Name: %s\n", agentCfg.AgentName)
	fmt.Printf("   Server:    %s\n", agentCfg.ServerURL)
	fmt.Println("🚀 This node will now automatically push network inventories after each scan.")
}

func handleAgentStatus() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("❌ Failed to load configuration: %v", err)
	}

	database, err := db.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("❌ Failed to open database: %v", err)
	}
	defer database.Close()

	agentCfg, err := federation.LoadAgentConfig(database)
	if err != nil || !agentCfg.IsPaired() {
		fmt.Println("⚪ Federation Status: Not paired")
		fmt.Println("   Use 'lanmap agent pair --server <URL> --pin <PIN>' to pair with a central server.")
		return
	}

	fmt.Println("🟢 Federation Status: Paired")
	fmt.Printf("   Agent ID:  %s\n", agentCfg.AgentID)
	fmt.Printf("   Site Name: %s\n", agentCfg.AgentName)
	fmt.Printf("   Server:    %s\n", agentCfg.ServerURL)
}

func handleAgentUnpair() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("❌ Failed to load configuration: %v", err)
	}

	database, err := db.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("❌ Failed to open database: %v", err)
	}
	defer database.Close()

	if err := federation.ClearAgentConfig(database); err != nil {
		log.Fatalf("❌ Failed to clear agent configuration: %v", err)
	}

	fmt.Println("✅ Successfully cleared federation agent pairing configuration.")
}

func handleAgentReport() {
	cfg, err := config.LoadConfig()
	if err != nil {
		log.Fatalf("❌ Failed to load configuration: %v", err)
	}

	database, err := db.Open(cfg.DBPath)
	if err != nil {
		log.Fatalf("❌ Failed to open database: %v", err)
	}
	defer database.Close()

	agentCfg, err := federation.LoadAgentConfig(database)
	if err != nil || !agentCfg.IsPaired() {
		log.Fatalf("❌ This node is not paired. Run 'lanmap agent pair' first.")
	}

	fmt.Printf("📡 Pushing local inventory to central server %s...\n", agentCfg.ServerURL)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	pushFederationReportIfPaired(ctx, database)
	fmt.Println("✅ Report process finished.")
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
