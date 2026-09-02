//go:build darwin

package service

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
)

type launchdManager struct {
	plistPath string
	label     string
}

// NewServiceManager creates a macOS launchd service manager
func NewServiceManager() (ServiceManager, error) {
	usr, err := user.Current()
	if err != nil {
		return nil, err
	}
	agentsDir := filepath.Join(usr.HomeDir, "Library", "LaunchAgents")
	_ = os.MkdirAll(agentsDir, 0755)

	label := "com.lanmap.service"
	plistPath := filepath.Join(agentsDir, label+".plist")

	return &launchdManager{
		plistPath: plistPath,
		label:     label,
	}, nil
}

func (m *launchdManager) Install() error {
	execPath, err := os.Executable()
	if err != nil {
		return err
	}
	execPath, _ = filepath.Abs(execPath)
	dir := filepath.Dir(execPath)

	plistContent := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>%s</string>
    <key>ProgramArguments</key>
    <array>
        <string>%s</string>
    </array>
    <key>WorkingDirectory</key>
    <string>%s</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>%s/lanmap.log</string>
    <key>StandardErrorPath</key>
    <string>%s/lanmap.err.log</string>
</dict>
</plist>`, m.label, execPath, dir, dir, dir)

	if err := os.WriteFile(m.plistPath, []byte(plistContent), 0644); err != nil {
		return fmt.Errorf("failed to write launchd plist: %w", err)
	}

	_ = exec.Command("launchctl", "unload", m.plistPath).Run()
	if err := exec.Command("launchctl", "load", m.plistPath).Run(); err != nil {
		return fmt.Errorf("failed to load launchd service: %w", err)
	}

	fmt.Printf("Service installed and loaded successfully to %s\n", m.plistPath)
	return nil
}

func (m *launchdManager) Uninstall() error {
	_ = exec.Command("launchctl", "unload", m.plistPath).Run()
	_ = os.Remove(m.plistPath)
	fmt.Println("Service uninstalled successfully.")
	return nil
}

func (m *launchdManager) Start() error {
	out, err := exec.Command("launchctl", "start", m.label).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to start service: %s (%w)", string(out), err)
	}
	fmt.Println("Service started.")
	return nil
}

func (m *launchdManager) Stop() error {
	out, err := exec.Command("launchctl", "stop", m.label).CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to stop service: %s (%w)", string(out), err)
	}
	fmt.Println("Service stopped.")
	return nil
}

func (m *launchdManager) Restart() error {
	_ = m.Stop()
	return m.Start()
}

func (m *launchdManager) Status() (string, error) {
	out, err := exec.Command("launchctl", "list", m.label).CombinedOutput()
	if err != nil {
		return fmt.Sprintf("Service is stopped or not loaded: %s", string(out)), nil
	}
	return string(out), nil
}
