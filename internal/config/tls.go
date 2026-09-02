package config

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// EnsureSelfSignedCert checks if valid cert/key exist at certPath/keyPath, or generates new self-signed pair (10.1)
func EnsureSelfSignedCert(certPath, keyPath string) error {
	_ = os.MkdirAll(filepath.Dir(certPath), 0755)
	_ = os.MkdirAll(filepath.Dir(keyPath), 0755)

	// Check if already exists and valid
	if certBytes, err := os.ReadFile(certPath); err == nil {
		block, _ := pem.Decode(certBytes)
		if block != nil {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err == nil && time.Now().Add(30*24*time.Hour).Before(cert.NotAfter) {
				// Certificate exists and has more than 30 days validity
				return nil
			}
		}
	}

	// Generate RSA 2048-bit key
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"lanmap self-signed"},
			CommonName:   "lanmap",
		},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1"), net.ParseIP("0.0.0.0")},
		DNSNames:              []string{"localhost"},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	certOut, err := os.Create(certPath)
	if err != nil {
		return fmt.Errorf("failed to create cert file: %w", err)
	}
	defer certOut.Close()
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return err
	}

	keyOut, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to create key file: %w", err)
	}
	defer keyOut.Close()
	privBytes := x509.MarshalPKCS1PrivateKey(priv)
	if err := pem.Encode(keyOut, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: privBytes}); err != nil {
		return err
	}

	log.Printf("[INFO] Generated self-signed TLS certificate at %s and %s", certPath, keyPath)
	return nil
}

// GetTLSKeyPair loads TLS certificate pair, falling back to default self-signed cert
func GetTLSKeyPair(customCertPath, customKeyPath, defaultCertPath, defaultKeyPath string) (tls.Certificate, error) {
	if customCertPath != "" && customKeyPath != "" {
		cert, err := tls.LoadX509KeyPair(customCertPath, customKeyPath)
		if err == nil {
			return cert, nil
		}
		log.Printf("[WARN] Failed to load custom TLS cert pair (%s, %s): %v. Falling back to self-signed.", customCertPath, customKeyPath, err)
	}

	if err := EnsureSelfSignedCert(defaultCertPath, defaultKeyPath); err != nil {
		return tls.Certificate{}, err
	}

	return tls.LoadX509KeyPair(defaultCertPath, defaultKeyPath)
}
