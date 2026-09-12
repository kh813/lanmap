//go:build !windows

package pid

import (
	"os"
	"syscall"
)

func isProcessRunning(pid int) bool {
	process, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	// On Unix, FindProcess always succeeds. Sending signal 0 checks if the process exists and is alive.
	err = process.Signal(syscall.Signal(0))
	return err == nil
}

func killProcess(pid int) error {
	process, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return process.Signal(syscall.SIGTERM)
}
