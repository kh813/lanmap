package pid

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// ErrAlreadyRunning is returned when a running instance of lanmap is detected
var ErrAlreadyRunning = errors.New("lanmap is already running")

// Manager manages process PID locking and lifecycle
type Manager struct {
	path string
}

// NewManager creates a new PID manager
func NewManager(path string) *Manager {
	return &Manager{path: path}
}

// Path returns the PID file path
func (m *Manager) Path() string {
	return m.path
}

// Acquire writes the current process PID to the PID file.
// If another instance of the process is already running, it returns ErrAlreadyRunning and the active PID.
func (m *Manager) Acquire() (int, error) {
	if runningPID, running := m.GetRunningPID(); running {
		return runningPID, fmt.Errorf("%w (PID: %d)", ErrAlreadyRunning, runningPID)
	}

	pid := os.Getpid()
	content := fmt.Sprintf("%d\n", pid)
	if err := os.WriteFile(m.path, []byte(content), 0644); err != nil {
		return 0, fmt.Errorf("failed to write PID file at %s: %w", m.path, err)
	}

	return pid, nil
}

// Release removes the PID file if it matches the current process PID
func (m *Manager) Release() {
	data, err := os.ReadFile(m.path)
	if err != nil {
		return
	}

	pidStr := strings.TrimSpace(string(data))
	pid, err := strconv.Atoi(pidStr)
	if err == nil && pid == os.Getpid() {
		_ = os.Remove(m.path)
	}
}

// GetRunningPID returns the stored PID and whether that process is currently alive
func (m *Manager) GetRunningPID() (int, bool) {
	data, err := os.ReadFile(m.path)
	if err != nil {
		return 0, false
	}

	pidStr := strings.TrimSpace(string(data))
	pid, err := strconv.Atoi(pidStr)
	if err != nil || pid <= 0 {
		return 0, false
	}

	if isProcessRunning(pid) {
		return pid, true
	}

	return pid, false
}

// Stop sends termination signal to the running process and waits for it to exit
func (m *Manager) Stop() (int, error) {
	pid, running := m.GetRunningPID()
	if !running {
		_ = os.Remove(m.path) // Clean up stale PID file if process already died
		return 0, fmt.Errorf("lanmap is not running")
	}

	if err := killProcess(pid); err != nil {
		return pid, fmt.Errorf("failed to signal process %d: %w", pid, err)
	}

	// Wait up to 5 seconds for process to exit
	for i := 0; i < 50; i++ {
		time.Sleep(100 * time.Millisecond)
		if !isProcessRunning(pid) {
			_ = os.Remove(m.path)
			return pid, nil
		}
	}

	_ = os.Remove(m.path)
	return pid, nil
}
