package pid

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestPIDManager_AcquireAndRelease(t *testing.T) {
	tempDir := t.TempDir()
	pidFile := filepath.Join(tempDir, "test.pid")

	mgr := NewManager(pidFile)

	// 1. First acquire should succeed
	pid, err := mgr.Acquire()
	if err != nil {
		t.Fatalf("First Acquire failed: %v", err)
	}
	if pid != os.Getpid() {
		t.Errorf("expected pid %d, got %d", os.Getpid(), pid)
	}

	// 2. Second acquire from same process (or another) should fail with ErrAlreadyRunning
	runningPID, err := mgr.Acquire()
	if err == nil {
		t.Fatalf("expected second Acquire to fail, but it succeeded")
	}
	if !errors.Is(err, ErrAlreadyRunning) {
		t.Errorf("expected ErrAlreadyRunning, got %v", err)
	}
	if runningPID != os.Getpid() {
		t.Errorf("expected runningPID %d, got %d", os.Getpid(), runningPID)
	}

	// 3. Verify GetRunningPID
	rPID, isRunning := mgr.GetRunningPID()
	if !isRunning || rPID != os.Getpid() {
		t.Errorf("expected running PID %d, got %d (running=%v)", os.Getpid(), rPID, isRunning)
	}

	// 4. Release should remove the file
	mgr.Release()

	if _, err := os.Stat(pidFile); !os.IsNotExist(err) {
		t.Errorf("expected PID file to be removed after Release, but it still exists")
	}

	// 5. Stale PID file test (simulate dead process)
	stalePID := 99999999 // Very unlikely to exist
	_ = os.WriteFile(pidFile, []byte(fmt.Sprintf("%d\n", stalePID)), 0644)

	newPID, err := mgr.Acquire()
	if err != nil {
		t.Fatalf("Acquire over stale PID file should succeed, got error: %v", err)
	}
	if newPID != os.Getpid() {
		t.Errorf("expected newPID %d, got %d", os.Getpid(), newPID)
	}

	mgr.Release()
}
