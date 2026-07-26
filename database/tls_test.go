package database

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func generateTestCertAndKey(t *testing.T) ([]byte, []byte) {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Test Org"}},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})

	return certPEM, keyPEM
}

func TestBuildTLSConfigModes(t *testing.T) {
	// Test disable mode
	cfg, err := buildTLSConfig("disable", "", "", "", "")
	if err != nil || cfg != nil {
		t.Errorf("Expected nil config for disable mode, got cfg: %v, err: %v", cfg, err)
	}

	// Test empty mode
	cfg, err = buildTLSConfig("", "", "", "", "")
	if err != nil || cfg != nil {
		t.Errorf("Expected nil config for empty mode, got cfg: %v, err: %v", cfg, err)
	}

	// Test require mode
	cfg, err = buildTLSConfig("require", "", "", "", "")
	if err != nil || cfg == nil {
		t.Fatalf("Expected non-nil config for require mode, got err: %v", err)
	}
	if !cfg.InsecureSkipVerify {
		t.Errorf("Expected InsecureSkipVerify to be true in require mode")
	}

	// Test verify-full mode with server name
	cfg, err = buildTLSConfig("verify-full", "db.example.com", "", "", "")
	if err != nil || cfg == nil {
		t.Fatalf("Expected non-nil config for verify-full mode, got err: %v", err)
	}
	if cfg.ServerName != "db.example.com" {
		t.Errorf("Expected ServerName 'db.example.com', got %q", cfg.ServerName)
	}
}

func TestBuildTLSConfigWithCertificates(t *testing.T) {
	tempDir := t.TempDir()
	certPEM, keyPEM := generateTestCertAndKey(t)

	certPath := filepath.Join(tempDir, "client.crt")
	keyPath := filepath.Join(tempDir, "client.key")
	caPath := filepath.Join(tempDir, "ca.crt")

	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		t.Fatalf("Failed to write cert file: %v", err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatalf("Failed to write key file: %v", err)
	}
	if err := os.WriteFile(caPath, certPEM, 0o600); err != nil {
		t.Fatalf("Failed to write CA file: %v", err)
	}

	// Test full mTLS and custom CA configuration
	cfg, err := buildTLSConfig("verify-ca", "server.com", caPath, certPath, keyPath)
	if err != nil || cfg == nil {
		t.Fatalf("Failed to build TLS config with certs: %v", err)
	}

	if cfg.RootCAs == nil {
		t.Errorf("Expected RootCAs pool to be initialized")
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("Expected 1 client certificate, got %d", len(cfg.Certificates))
	}

	// Test single certificate path provided error
	_, err = buildTLSConfig("verify-ca", "", "", certPath, "")
	if err == nil {
		t.Errorf("Expected error when only client_cert_path is provided")
	}
}

func TestBuildTLSConfigErrors(t *testing.T) {
	// Test non-existent root cert
	_, err := buildTLSConfig("verify-ca", "", "non_existent_ca.crt", "", "")
	if err == nil {
		t.Errorf("Expected error for missing root CA file")
	}

	// Test non-existent client cert
	tempDir := t.TempDir()
	keyPath := filepath.Join(tempDir, "client.key")
	_ = os.WriteFile(keyPath, []byte("fake_key"), 0o600)
	_, err = buildTLSConfig("verify-ca", "", "", "non_existent_cert.crt", keyPath)
	if err == nil {
		t.Errorf("Expected error for missing client cert file")
	}

	// Test malformed client cert pair
	certPath := filepath.Join(tempDir, "malformed.crt")
	_ = os.WriteFile(certPath, []byte("invalid_cert"), 0o600)
	_, err = buildTLSConfig("verify-ca", "", "", certPath, keyPath)
	if err == nil {
		t.Errorf("Expected error for malformed certificate pair")
	}
}
