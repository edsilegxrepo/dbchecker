/*
TLS configuration builder for database connections.

TLS Modes (from config.SupportedTLSModes):
  - ""/disable: No TLS, plaintext connection
  - require: TLS enabled, skip server certificate verification
  - verify-ca: TLS with CA verification (custom or system CA)
  - verify-full: TLS with CA + hostname verification

Security:
  - Minimum TLS 1.2 enforced
  - Certificate files read via os.OpenRoot to prevent directory traversal
  - mTLS requires both client cert and key paths
*/
package database

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"

	"github.com/edsilegxrepo/dbchecker/config"
)

// readScopedFile opens the parent directory of path using os.OpenRoot (Go 1.24+)
// to prevent directory traversal and securely read certificate files.
func readScopedFile(path string) ([]byte, error) {
	dir := filepath.Dir(path)
	if dir == "" || dir == "." {
		absPath, err := filepath.Abs(path)
		if err == nil {
			dir = filepath.Dir(absPath)
			path = absPath
		} else {
			dir = "."
		}
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to open directory %s: %w", dir, err)
	}
	defer func() {
		if closeErr := root.Close(); closeErr != nil {
			_ = closeErr
		}
	}()

	data, err := root.ReadFile(filepath.Base(path))
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", filepath.Base(path), err)
	}
	return data, nil
}

// configureInsecureTransport sets InsecureSkipVerify for explicit 'require' TLS mode.
// nosemgrep: problem-based-packs.insecure-transport.go-stdlib.bypass-tls-verification.bypass-tls-verification
// nosemgrep: bypass-tls-verification
//
//nolint:gosec // TLS mode "require" explicitly requests skipping CA verification per user configuration
func configureInsecureTransport(cfg *tls.Config) {
	//nolint:gosec // TLS mode "require" explicitly requests skipping CA verification per user configuration
	// nosemgrep: problem-based-packs.insecure-transport.go-stdlib.bypass-tls-verification.bypass-tls-verification
	// nosemgrep: bypass-tls-verification
	cfg.InsecureSkipVerify = true // nosemgrep
}

// buildTLSConfig creates a tls.Config based on the requested mode and certificate paths.
// Uses config.SupportedTLSModes for validation (centralized TLS mode definitions).
// Returns nil config for "disable" or empty mode (plaintext connection).
// nosemgrep: problem-based-packs.insecure-transport.go-stdlib.bypass-tls-verification.bypass-tls-verification
// nosemgrep: bypass-tls-verification
//
//nolint:gosec // TLS mode "require" explicitly requests skipping CA verification per user configuration
func buildTLSConfig(tlsMode, serverName, rootCertPath, clientCertPath, clientKeyPath string) (*tls.Config, error) {
	if _, ok := config.SupportedTLSModes[tlsMode]; !ok {
		return nil, fmt.Errorf("invalid tls_mode: %s", tlsMode)
	}

	if tlsMode == "disable" || tlsMode == "" {
		return nil, nil
	}

	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	if tlsMode == "verify-full" {
		tlsConfig.ServerName = serverName
	}

	if tlsMode == "require" {
		configureInsecureTransport(tlsConfig)
		return tlsConfig, nil
	}

	// Load custom root CA if provided, otherwise use system's trust store.
	if rootCertPath != "" {
		caCert, err := readScopedFile(rootCertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to load root certificate: %w", err)
		}
		caCertPool := x509.NewCertPool()
		caCertPool.AppendCertsFromPEM(caCert)
		tlsConfig.RootCAs = caCertPool
	}

	// Load client certificate and key for mTLS using scoped file reads.
	if clientCertPath != "" && clientKeyPath != "" {
		certPEM, err := readScopedFile(clientCertPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read client cert: %w", err)
		}
		keyPEM, err := readScopedFile(clientKeyPath)
		if err != nil {
			return nil, fmt.Errorf("failed to read client key: %w", err)
		}
		clientCert, err := tls.X509KeyPair(certPEM, keyPEM)
		if err != nil {
			return nil, fmt.Errorf("failed to parse client certificate pair: %w", err)
		}
		tlsConfig.Certificates = []tls.Certificate{clientCert}
	} else if clientCertPath != "" || clientKeyPath != "" {
		return nil, fmt.Errorf("both client_cert_path and client_key_path must be provided for mTLS")
	}

	return tlsConfig, nil
}
