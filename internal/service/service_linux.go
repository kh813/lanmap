//go:build linux

package service

import (
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
)

type systemdManager struct {
	unitPath string
}

// NewServiceManager creates a Linux systemd service manager
func NewServiceManager() (ServiceManager, error) {
	// Support unprivileged user systemd service or system unit
	usr, err := user.Current()
	if err == nil && usr.Uid != "0" {
		userUnitDir := filepath.Join(usr.HomeDir, ".config", "systemd", "user")
		_ = os.MkdirAll(userUnitDir, 0755)
		return &systemdManager{unitPath: filepath.Join(userUnitDir, "lanmap.service")}, nil
	}
	return &systemdManager{unitPath: "/etc/systemd/system/lanmap.service"}, nil
}

func (s *systemdManager) isUserUnit() bool {
	usr, _ := user.Current()
	return usr != nil && usr.Uid != "0"
}

func (s *systemdManager) runSystemctl(args ...string) (string, error) {
	if s.isUserUnit() {
		args = append([]string{"--user"}, args...)
	}
	cmd := exec.Command("systemctl", args...)
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func (s *systemdManager) Install() error {
	execPath, err := os.Executable()
	if err != nil {
		return err
	}
	execPath, _ = filepath.Abs(execPath)

	content := fmt.Sprintf(`[Unit]
Description=lanmap - LAN Host Manager & Security Detector
After=network.target

[Service]
Type=simple
ExecStart=%s
Restart=always
RestartSec=5
WorkingDirectory=%s

[Install]
WantedBy=default.target
`, execPath, filepath.Dir(execPath))

	if err := os.WriteFile(s.unitPath, []byte(content), 0644); err != nil {
		return fmt.Errorf("failed to write systemd unit (%s): %w", s.unitPath, err)
	}

	_, _ = s.runSystemctl("daemon-reload")
	_, _ = s.runSystemctl("enable", "lanmap.service")
	fmt.Printf("Service installed successfully to %s\n", s.unitPath)
	return nil
}

func (s *systemdManager) Uninstall() error {
	_, _ = s.runSystemctl("stop", "lanmap.service")
	_, _ = s.runSystemctl("disable", "lanmap.service")
	_ = os.Remove(s.unitPath)
	_, _ = s.runSystemctl("daemon-reload")
	fmt.Println("Service uninstalled successfully.")
	return nil
}

func (s *systemdManager) Start() error {
	out, err := s.runSystemctl("start", "lanmap.service")
	if err != nil {
		return fmt.Errorf("failed to start service: %s (%w)", out, err)
	}
	fmt.Println("Service started.")
	return nil
}

func (s *systemdManager) Stop() error {
	out, err := s.runSystemctl("stop", "lanmap.service")
	if err != nil {
		return fmt.Errorf("failed to stop service: %s (%w)", out, err)
	}
	fmt.Println("Service stopped.")
	return nil
}

func (s *systemdManager) Restart() error {
	out, err := s.runSystemctl("restart", "lanmap.service")
	if err != nil {
		return fmt.Errorf("failed to restart service: %s (%w)", out, err)
	}
	fmt.Println("Service restarted.")
	return nil
}

func (s *systemdManager) Status() (string, error) {
	out, _ := s.runSystemctl("status", "lanmap.service")
	return out, nil
}
