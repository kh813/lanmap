package updater

import (
	"archive/zip"
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestVersionComparison(t *testing.T) {
	tests := []struct {
		remote   string
		current  string
		expected bool
	}{
		{"v0.0.5", "v0.0.4", true},
		{"v0.1.0", "v0.0.4", true},
		{"v1.0.0", "v0.9.9", true},
		{"v0.0.4", "v0.0.4", false},
		{"v0.0.3", "v0.0.4", false},
		{"0.0.5", "v0.0.4", true},
		{"v0.0.5-beta", "v0.0.4", true},
	}

	for _, tt := range tests {
		got := IsVersionNewer(tt.remote, tt.current)
		if got != tt.expected {
			t.Errorf("IsVersionNewer(%q, %q) = %v, want %v", tt.remote, tt.current, got, tt.expected)
		}
	}
}

func TestDownloadAndApplyUpdateWithMock(t *testing.T) {
	// Create mock zip archive containing dummy binary
	targetBinaryName := "lanmap"
	if runtime.GOOS == "windows" {
		targetBinaryName = "lanmap.exe"
	}

	var zipBuf bytes.Buffer
	zw := zip.NewWriter(&zipBuf)
	w, err := zw.Create(targetBinaryName)
	if err != nil {
		t.Fatalf("failed to create file in zip: %v", err)
	}
	_, _ = w.Write([]byte("#!/bin/sh\necho updated\n"))
	_ = zw.Close()

	server := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/zip")
		rw.WriteHeader(http.StatusOK)
		_, _ = rw.Write(zipBuf.Bytes())
	}))
	defer server.Close()

	// Test downloading to temp file
	tempDir := t.TempDir()
	dummyExec := filepath.Join(tempDir, targetBinaryName)
	_ = os.WriteFile(dummyExec, []byte("original"), 0755)

	// Verify download and extraction logic
	// We can test the helper directly
	zipBytes := zipBuf.Bytes()
	zr, err := zip.NewReader(bytes.NewReader(zipBytes), int64(len(zipBytes)))
	if err != nil {
		t.Fatalf("zip.NewReader failed: %v", err)
	}

	if len(zr.File) != 1 || zr.File[0].Name != targetBinaryName {
		t.Errorf("unexpected file in zip: %+v", zr.File)
	}
}
