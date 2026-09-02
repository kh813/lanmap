//go:build windows

package service

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/windows/svc"
	"golang.org/x/sys/windows/svc/mgr"
)

const serviceName = "lanmap"

type windowsServiceManager struct{}

// NewServiceManager creates a Windows SCM service manager
func NewServiceManager() (ServiceManager, error) {
	return &windowsServiceManager{}, nil
}

func (w *windowsServiceManager) Install() error {
	m, err := mgr.Connect()
	if err != nil {
		return fmt.Errorf("failed to connect to service manager: %w", err)
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err == nil {
		s.Close()
		return fmt.Errorf("service %s already exists", serviceName)
	}

	execPath, err := os.Executable()
	if err != nil {
		return err
	}
	execPath, _ = filepath.Abs(execPath)

	cfg := mgr.Config{
		DisplayName: "lanmap - LAN Host Manager & Security Detector",
		Description: "LAN network monitoring and rogue host security detector service",
		StartType:   mgr.StartAutomatic,
	}

	s, err = m.CreateService(serviceName, execPath, cfg)
	if err != nil {
		return fmt.Errorf("failed to create service: %w", err)
	}
	defer s.Close()

	fmt.Printf("Service %s installed successfully.\n", serviceName)
	return nil
}

func (w *windowsServiceManager) Uninstall() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Errorf("service %s is not installed", serviceName)
	}
	defer s.Close()

	_ = s.Delete()
	fmt.Printf("Service %s uninstalled successfully.\n", serviceName)
	return nil
}

func (w *windowsServiceManager) Start() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()

	err = s.Start()
	if err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}
	fmt.Printf("Service %s started.\n", serviceName)
	return nil
}

func (w *windowsServiceManager) Stop() error {
	m, err := mgr.Connect()
	if err != nil {
		return err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return err
	}
	defer s.Close()

	_, err = s.Control(svc.Stop)
	if err != nil {
		return fmt.Errorf("failed to stop service: %w", err)
	}
	fmt.Printf("Service %s stopped.\n", serviceName)
	return nil
}

func (w *windowsServiceManager) Restart() error {
	_ = w.Stop()
	time.Sleep(1 * time.Second)
	return w.Start()
}

func (w *windowsServiceManager) Status() (string, error) {
	m, err := mgr.Connect()
	if err != nil {
		return "", err
	}
	defer m.Disconnect()

	s, err := m.OpenService(serviceName)
	if err != nil {
		return fmt.Sprintf("Service %s not found: %v", serviceName, err), nil
	}
	defer s.Close()

	status, err := s.Query()
	if err != nil {
		return "", err
	}

	stateStr := "UNKNOWN"
	switch status.State {
	case svc.Stopped:
		stateStr = "STOPPED"
	case svc.StartPending:
		stateStr = "START_PENDING"
	case svc.StopPending:
		stateStr = "STOP_PENDING"
	case svc.Running:
		stateStr = "RUNNING"
	}

	return fmt.Sprintf("Service %s state: %s", serviceName, stateStr), nil
}
