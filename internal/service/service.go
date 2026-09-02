package service

import (
	"fmt"
)

// ServiceManager defines OS-independent service management interface
type ServiceManager interface {
	Install() error
	Uninstall() error
	Start() error
	Stop() error
	Restart() error
	Status() (string, error)
}

// HandleCommand routes CLI service subcommands
func HandleCommand(action string) error {
	mgr, err := NewServiceManager()
	if err != nil {
		return err
	}

	switch action {
	case "install":
		return mgr.Install()
	case "uninstall":
		return mgr.Uninstall()
	case "start":
		return mgr.Start()
	case "stop":
		return mgr.Stop()
	case "restart":
		return mgr.Restart()
	case "status":
		status, err := mgr.Status()
		if err != nil {
			return err
		}
		fmt.Println(status)
		return nil
	default:
		return fmt.Errorf("unknown service action: %s (available: install, uninstall, start, stop, restart, status)", action)
	}
}
