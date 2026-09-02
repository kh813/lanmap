package config

import (
	"path/filepath"
	"testing"
)

func TestSelfSignedCertGeneration(t *testing.T) {
	tempDir := t.TempDir()
	certPath := filepath.Join(tempDir, "cert.pem")
	keyPath := filepath.Join(tempDir, "key.pem")

	// 1. Generate cert
	err := EnsureSelfSignedCert(certPath, keyPath)
	if err != nil {
		t.Fatalf("EnsureSelfSignedCert failed: %v", err)
	}

	// 2. Load cert pair
	cert, err := GetTLSKeyPair("", "", certPath, keyPath)
	if err != nil {
		t.Fatalf("GetTLSKeyPair failed: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Errorf("expected non-empty certificate")
	}

	// 3. Ensure idempotency (doesn't fail or overwrite if valid)
	err = EnsureSelfSignedCert(certPath, keyPath)
	if err != nil {
		t.Fatalf("Second EnsureSelfSignedCert failed: %v", err)
	}
}
