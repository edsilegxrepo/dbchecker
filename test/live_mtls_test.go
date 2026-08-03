//go:build integration
// +build integration

package test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/edsilegxrepo/secretprotector/pkg/libsecsecrets"

	"github.com/edsilegxrepo/dbchecker/config"
	"github.com/edsilegxrepo/dbchecker/database"
	"github.com/edsilegxrepo/dbchecker/pkg/dbchecker"
	"github.com/edsilegxrepo/dbchecker/testutil"
)

const (
	// Container process Linux UIDs/GIDs for cert directory ownership
	postgresContainerUIDGID = "70:70"       // postgres:18-alpine daemon user
	mysqlContainerUIDGID    = "999:999"     // mysql:8.4 daemon user
	mongoContainerUIDGID    = "999:999"     // mongo:8.0 daemon user
	mssqlContainerUIDGID    = "10001:0"     // azure-sql-edge daemon user
	oracleContainerUIDGID   = "54321:54321" // oracle-xe:21-slim daemon user
)

// certSet holds PEM-encoded certificate authority, server, client, and untrusted client certs.
type certSet struct {
	caCertPEM        []byte
	caKeyPEM         []byte
	serverCertPEM    []byte
	serverKeyPEM     []byte
	clientCertPEM    []byte
	clientKeyPEM     []byte
	badClientCertPEM []byte
	badClientKeyPEM  []byte
}

// generateLiveMTLSCerts creates in-memory x509 Root CA, Server (with 127.0.0.1/localhost SANs), Client, and Bad Client keypairs.
func generateLiveMTLSCerts(t *testing.T) certSet {
	t.Helper()

	// 1. Generate Root CA
	caPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate CA private key: %v", err)
	}
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1000),
		Subject:               pkix.Name{Organization: []string{"DBChecker Test CA"}},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caCertBytes, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("Failed to create CA cert: %v", err)
	}
	caCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caCertBytes})
	caKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(caPriv)})

	// Parse CA cert struct for signing server and client certs
	caCert, err := x509.ParseCertificate(caCertBytes)
	if err != nil {
		t.Fatalf("Failed to parse CA cert: %v", err)
	}

	// 2. Generate Server Certificate signed by CA (with 127.0.0.1 & localhost SANs)
	serverPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate server private key: %v", err)
	}
	serverTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1001),
		Subject:               pkix.Name{CommonName: "localhost", Organization: []string{"DBChecker Server"}},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}
	serverCertBytes, err := x509.CreateCertificate(rand.Reader, serverTemplate, caCert, &serverPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("Failed to create server cert: %v", err)
	}
	serverCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: serverCertBytes})
	serverKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(serverPriv)})

	// 3. Generate Valid Client Certificate signed by CA
	clientPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate client private key: %v", err)
	}
	clientTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1002),
		Subject:               pkix.Name{CommonName: "testuser", Organization: []string{"DBChecker Client"}},
		NotBefore:             time.Now().Add(-1 * time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	clientCertBytes, err := x509.CreateCertificate(rand.Reader, clientTemplate, caCert, &clientPriv.PublicKey, caPriv)
	if err != nil {
		t.Fatalf("Failed to create client cert: %v", err)
	}
	clientCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: clientCertBytes})
	clientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(clientPriv)})

	// 4. Generate Untrusted Bad Client Certificate (signed by a rogue CA)
	badCAPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	badCATemplate := &x509.Certificate{
		SerialNumber: big.NewInt(9999),
		Subject:      pkix.Name{Organization: []string{"Untrusted Rogue CA"}},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		IsCA:         true,
	}
	badCACertBytes, _ := x509.CreateCertificate(rand.Reader, badCATemplate, badCATemplate, &badCAPriv.PublicKey, badCAPriv)
	badCACert, _ := x509.ParseCertificate(badCACertBytes)

	badClientPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	badClientTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(9998),
		Subject:      pkix.Name{CommonName: "baduser"},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	badClientCertBytes, _ := x509.CreateCertificate(rand.Reader, badClientTemplate, badCACert, &badClientPriv.PublicKey, badCAPriv)
	badClientCertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: badClientCertBytes})
	badClientKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(badClientPriv)})

	return certSet{
		caCertPEM:        caCertPEM,
		caKeyPEM:         caKeyPEM,
		serverCertPEM:    serverCertPEM,
		serverKeyPEM:     serverKeyPEM,
		clientCertPEM:    clientCertPEM,
		clientKeyPEM:     clientKeyPEM,
		badClientCertPEM: badClientCertPEM,
		badClientKeyPEM:  badClientKeyPEM,
	}
}

// setupLiveMTLSCertDir writes certificates to disk with target UID:GID ownership and strict permissions.
func setupLiveMTLSCertDir(t *testing.T, cs certSet, targetUIDGID string) (hostCertDir, wslCertDir string) {
	t.Helper()

	if runtime.GOOS == "windows" {
		wslDir := fmt.Sprintf("/tmp/dbchecker_mtls_%d", time.Now().UnixNano())
		_ = exec.Command("wsl", "mkdir", "-p", wslDir).Run()

		writeWSLFile := func(filename string, content []byte) {
			b64 := base64.StdEncoding.EncodeToString(content)
			perm := "644"
			if strings.HasSuffix(filename, ".key") {
				perm = "600"
			}
			cmdStr := fmt.Sprintf("echo '%s' | base64 -d > %s/%s && chmod %s %s/%s", b64, wslDir, filename, perm, wslDir, filename)
			_ = exec.Command("wsl", "bash", "-c", cmdStr).Run()
		}

		serverPEM := append(cs.serverCertPEM, cs.serverKeyPEM...)
		clientPEM := append(cs.clientCertPEM, cs.clientKeyPEM...)

		writeWSLFile("ca.crt", cs.caCertPEM)
		writeWSLFile("server.crt", cs.serverCertPEM)
		writeWSLFile("server.key", cs.serverKeyPEM)
		writeWSLFile("server.pem", serverPEM)
		writeWSLFile("client.crt", cs.clientCertPEM)
		writeWSLFile("client.key", cs.clientKeyPEM)
		writeWSLFile("client.pem", clientPEM)
		writeWSLFile("bad_client.crt", cs.badClientCertPEM)
		writeWSLFile("bad_client.key", cs.badClientKeyPEM)

		// 1. Set the right container owner (chown)
		if targetUIDGID != "" {
			chownCmd := fmt.Sprintf("chown -R %s %s", targetUIDGID, wslDir)
			_ = exec.Command("wsl", "-u", "root", "bash", "-c", chownCmd).Run()
		}

		// 2. Set the right secure file permissions (chmod)
		chmodCmd := fmt.Sprintf("chmod 755 %s && chmod 644 %s/*.crt %s/*.pem && chmod 600 %s/*.key", wslDir, wslDir, wslDir, wslDir)
		_ = exec.Command("wsl", "-u", "root", "bash", "-c", chmodCmd).Run()

		localDir := t.TempDir()

		_ = os.WriteFile(filepath.Join(localDir, "ca.crt"), cs.caCertPEM, 0o600)
		_ = os.WriteFile(filepath.Join(localDir, "client.crt"), cs.clientCertPEM, 0o600)
		_ = os.WriteFile(filepath.Join(localDir, "client.key"), cs.clientKeyPEM, 0o600)
		_ = os.WriteFile(filepath.Join(localDir, "bad_client.crt"), cs.badClientCertPEM, 0o600)
		_ = os.WriteFile(filepath.Join(localDir, "bad_client.key"), cs.badClientKeyPEM, 0o600)

		t.Cleanup(func() {
			_ = exec.Command("wsl", "rm", "-rf", wslDir).Run()
		})

		return localDir, wslDir
	}

	// Linux native setup
	localDir := t.TempDir()
	serverPEM := append(cs.serverCertPEM, cs.serverKeyPEM...)
	clientPEM := append(cs.clientCertPEM, cs.clientKeyPEM...)

	files := map[string][]byte{
		"ca.crt":         cs.caCertPEM,
		"server.crt":     cs.serverCertPEM,
		"server.key":     cs.serverKeyPEM,
		"server.pem":     serverPEM,
		"client.crt":     cs.clientCertPEM,
		"client.key":     cs.clientKeyPEM,
		"client.pem":     clientPEM,
		"bad_client.crt": cs.badClientCertPEM,
		"bad_client.key": cs.badClientKeyPEM,
	}

	for fname, data := range files {
		p := filepath.Join(localDir, fname)
		perm := os.FileMode(0o644)
		if strings.HasSuffix(fname, ".key") {
			perm = os.FileMode(0o600)
		}
		if err := os.WriteFile(p, data, perm); err != nil {
			t.Fatalf("Failed to write cert file %s: %v", fname, err)
		}
	}

	// 1. Set the right container owner (chown) on Linux
	if targetUIDGID != "" {
		chownCmd := fmt.Sprintf("chown -R %s %s 2>/dev/null || sudo chown -R %s %s", targetUIDGID, localDir, targetUIDGID, localDir)
		_ = exec.Command("bash", "-c", chownCmd).Run()
	}

	// 2. Set the right secure file permissions (chmod) on Linux
	chmodCmd := fmt.Sprintf("chmod 755 %s && chmod 644 %s/*.crt %s/*.pem && chmod 600 %s/*.key", localDir, localDir, localDir, localDir)
	_ = exec.Command("bash", "-c", chmodCmd).Run()

	return localDir, localDir
}

// TestLivePostgresMTLS spins up a live PostgreSQL 18 container configured for mTLS and tests verify-full.
func TestLivePostgresMTLS(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping live mTLS tests in -short mode.")
	}
	if !testutil.IsDockerAvailable() {
		t.Skip("Skipping live mTLS tests: Docker daemon not available.")
	}

	testutil.PruneContainers("dbchecker")
	cs := generateLiveMTLSCerts(t)
	localCertDir, mountCertDir := setupLiveMTLSCertDir(t, cs, postgresContainerUIDGID)

	prefix := testutil.GetDockerPrefix()
	containerName := fmt.Sprintf("dbchecker-pg-mtls-%d", time.Now().UnixNano())
	_ = exec.Command(prefix[0], append(prefix[1:], "rm", "-f", containerName)...).Run()

	// Start PostgreSQL 18 container enforcing SSL
	args := append(prefix[1:], "run", "-d", "--name", containerName,
		"-v", fmt.Sprintf("%s:/certs:ro", mountCertDir),
		"-p", "0:5432",
		"-e", "POSTGRES_USER=testuser",
		"-e", "POSTGRES_PASSWORD=secretpass",
		"-e", "POSTGRES_DB=testdb",
		"postgres:18-alpine",
		"postgres",
		"-c", "ssl=on",
		"-c", "ssl_cert_file=/certs/server.crt",
		"-c", "ssl_key_file=/certs/server.key",
		"-c", "ssl_ca_file=/certs/ca.crt",
	)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, prefix[0], args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to start PostgreSQL mTLS container: %v. Output: %s", err, string(out))
	}

	t.Cleanup(func() {
		_ = exec.Command(prefix[0], append(prefix[1:], "rm", "-f", containerName)...).Run()
		if os.Getenv("PRESERVE_DOCKER_IMAGES") != "1" {
			_ = exec.Command(prefix[0], append(prefix[1:], "rmi", "-f", "postgres:18-alpine")...).Run()
		}
	})

	// Inspect host dynamic port
	portArgs := append(prefix[1:], "port", containerName, "5432/tcp")
	portOut, err := exec.Command(prefix[0], portArgs...).CombinedOutput()
	if err != nil {
		portArgs = append(prefix[1:], "port", containerName, "5432")
		portOut, _ = exec.Command(prefix[0], portArgs...).CombinedOutput()
	}
	rawPortStr := strings.TrimSpace(string(portOut))
	idx := strings.LastIndex(rawPortStr, ":")
	if idx == -1 {
		t.Fatalf("Failed to parse host port for PostgreSQL mTLS: %s", rawPortStr)
	}
	portNum, _ := strconv.Atoi(rawPortStr[idx+1:])

	// Build mTLS database config
	caPath := filepath.Join(localCertDir, "ca.crt")
	clientCertPath := filepath.Join(localCertDir, "client.crt")
	clientKeyPath := filepath.Join(localCertDir, "client.key")
	badCertPath := filepath.Join(localCertDir, "bad_client.crt")
	badKeyPath := filepath.Join(localCertDir, "bad_client.key")

	validCfg := config.DatabaseConfig{
		Type:           "postgres",
		Host:           "127.0.0.1",
		Port:           portNum,
		User:           "testuser",
		Name:           "testdb",
		TLSMode:        "verify-full",
		RootCertPath:   caPath,
		ClientCertPath: clientCertPath,
		ClientKeyPath:  clientKeyPath,
		HealthQuery:    "SELECT 1;",
	}

	// Wait for Postgres boot
	if err := testutil.WaitForDatabase(ctx, "postgres", validCfg, "secretpass", 30*time.Second); err != nil {
		t.Fatalf("PostgreSQL mTLS container boot timeout: %v", err)
	}

	// 1. Happy Path mTLS Connection
	t.Run("PostgreSQL_mTLS_Success", func(t *testing.T) {
		db, err := database.New("postgres")
		if err != nil {
			t.Fatalf("Failed to create postgres driver: %v", err)
		}
		defer func() {
			if closeErr := db.Close(); closeErr != nil {
				t.Errorf("PostgreSQL Close failed: %v", closeErr)
			}
		}()

		if err := db.Connect(ctx, validCfg, "secretpass"); err != nil {
			t.Fatalf("PostgreSQL mTLS Connect failed: %v", err)
		}
		if err := db.Ping(ctx); err != nil {
			t.Errorf("PostgreSQL mTLS Ping failed: %v", err)
		}
		if err := db.HealthCheck(ctx, validCfg.HealthQuery); err != nil {
			t.Errorf("PostgreSQL mTLS HealthCheck failed: %v", err)
		}
	})

	// 2. Negative Path: Untrusted Client Cert Rejection
	t.Run("PostgreSQL_mTLS_Untrusted_Cert_Rejection", func(t *testing.T) {
		badCfg := validCfg
		badCfg.ClientCertPath = badCertPath
		badCfg.ClientKeyPath = badKeyPath

		db, _ := database.New("postgres")
		defer func() {
			_ = db.Close()
		}()

		if err := db.Connect(ctx, badCfg, "secretpass"); err == nil {
			if pingErr := db.Ping(ctx); pingErr == nil {
				t.Errorf("Expected PostgreSQL mTLS to reject untrusted client cert, but ping succeeded")
			}
		}
	})

	// 3. Full CLI Scan Verification over mTLS
	t.Run("PostgreSQL_mTLS_CLI_Scan", func(t *testing.T) {
		tempDir := t.TempDir()
		configPath := filepath.Join(tempDir, "postgres_mtls_config.yaml")

		masterKey, _ := libsecsecrets.GenerateKey()
		t.Setenv("DB_SECRET_KEY", masterKey)

		var encOut, encErr bytes.Buffer
		exitCode := dbchecker.RunAppCLI([]string{"-encrypt", "secretpass"}, &encOut, &encErr)
		if exitCode != 0 {
			t.Fatalf("CLI encryption failed: %s", encErr.String())
		}
		encPass := strings.TrimSpace(encOut.String())

		yamlData := fmt.Sprintf(`
databases:
  live_postgres_mtls:
    type: postgres
    host: 127.0.0.1
    port: %d
    user: testuser
    name: testdb
    password: %s
    tls_mode: verify-full
    root_cert_path: %s
    client_cert_path: %s
    client_key_path: %s
    health_query: "SELECT 1;"
`, portNum, encPass, filepath.ToSlash(caPath), filepath.ToSlash(clientCertPath), filepath.ToSlash(clientKeyPath))

		if err := os.WriteFile(configPath, []byte(yamlData), 0o600); err != nil {
			t.Fatalf("Failed to write yaml config: %v", err)
		}

		var scanOut, scanErr bytes.Buffer
		exitCode = dbchecker.RunAppCLI([]string{"-config", configPath, "-json"}, &scanOut, &scanErr)
		if exitCode != 0 {
			t.Fatalf("CLI mTLS scan failed with exit code %d. Stderr: %s", exitCode, scanErr.String())
		}

		if !strings.Contains(scanOut.String(), "live_postgres_mtls") {
			t.Errorf("Expected scan output to contain live_postgres_mtls, got: %s", scanOut.String())
		}
	})
}

// TestLiveMySQLMTLS spins up a live MySQL 8.4 container configured for mTLS and tests verify-full mode.
func TestLiveMySQLMTLS(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping live mTLS tests in -short mode.")
	}
	if !testutil.IsDockerAvailable() {
		t.Skip("Skipping live mTLS tests: Docker daemon not available.")
	}

	testutil.PruneContainers("dbchecker")
	cs := generateLiveMTLSCerts(t)
	localCertDir, mountCertDir := setupLiveMTLSCertDir(t, cs, mysqlContainerUIDGID)

	prefix := testutil.GetDockerPrefix()
	containerName := fmt.Sprintf("dbchecker-mysql-mtls-%d", time.Now().UnixNano())
	_ = exec.Command(prefix[0], append(prefix[1:], "rm", "-f", containerName)...).Run()

	// Start MySQL 8.4 container enforcing SSL and secure transport
	args := append(prefix[1:], "run", "-d", "--name", containerName,
		"-v", fmt.Sprintf("%s:/certs:ro", mountCertDir),
		"-p", "0:3306",
		"-e", "MYSQL_ROOT_PASSWORD=secretpass",
		"-e", "MYSQL_DATABASE=testdb",
		"mysql:8.4",
		"--ssl-ca=/certs/ca.crt",
		"--ssl-cert=/certs/server.crt",
		"--ssl-key=/certs/server.key",
		"--require-secure-transport=ON",
	)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, prefix[0], args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to start MySQL mTLS container: %v. Output: %s", err, string(out))
	}

	t.Cleanup(func() {
		_ = exec.Command(prefix[0], append(prefix[1:], "rm", "-f", containerName)...).Run()
		if os.Getenv("PRESERVE_DOCKER_IMAGES") != "1" {
			_ = exec.Command(prefix[0], append(prefix[1:], "rmi", "-f", "mysql:8.4")...).Run()
		}
	})

	// Inspect host dynamic port
	portArgs := append(prefix[1:], "port", containerName, "3306/tcp")
	portOut, err := exec.Command(prefix[0], portArgs...).CombinedOutput()
	if err != nil {
		portArgs = append(prefix[1:], "port", containerName, "3306")
		portOut, _ = exec.Command(prefix[0], portArgs...).CombinedOutput()
	}
	rawPortStr := strings.TrimSpace(string(portOut))
	idx := strings.LastIndex(rawPortStr, ":")
	if idx == -1 {
		t.Fatalf("Failed to parse host port for MySQL mTLS: %s", rawPortStr)
	}
	portNum, _ := strconv.Atoi(rawPortStr[idx+1:])

	caPath := filepath.Join(localCertDir, "ca.crt")
	clientCertPath := filepath.Join(localCertDir, "client.crt")
	clientKeyPath := filepath.Join(localCertDir, "client.key")
	badCertPath := filepath.Join(localCertDir, "bad_client.crt")
	badKeyPath := filepath.Join(localCertDir, "bad_client.key")

	validCfg := config.DatabaseConfig{
		Type:           "mysql",
		Host:           "127.0.0.1",
		Port:           portNum,
		User:           "root",
		Name:           "testdb",
		TLSMode:        "verify-full",
		RootCertPath:   caPath,
		ClientCertPath: clientCertPath,
		ClientKeyPath:  clientKeyPath,
		HealthQuery:    "SELECT 1;",
	}

	// Wait for MySQL boot
	if err := testutil.WaitForDatabase(ctx, "mysql", validCfg, "secretpass", 95*time.Second); err != nil {
		t.Fatalf("MySQL mTLS container boot timeout: %v", err)
	}

	// 1. Happy Path mTLS Connection
	t.Run("MySQL_mTLS_Success", func(t *testing.T) {
		db, err := database.New("mysql")
		if err != nil {
			t.Fatalf("Failed to create mysql driver: %v", err)
		}
		defer func() {
			if closeErr := db.Close(); closeErr != nil {
				t.Errorf("MySQL Close failed: %v", closeErr)
			}
		}()

		if err := db.Connect(ctx, validCfg, "secretpass"); err != nil {
			t.Fatalf("MySQL mTLS Connect failed: %v", err)
		}
		if err := db.Ping(ctx); err != nil {
			t.Errorf("MySQL mTLS Ping failed: %v", err)
		}
		if err := db.HealthCheck(ctx, validCfg.HealthQuery); err != nil {
			t.Errorf("MySQL mTLS HealthCheck failed: %v", err)
		}
	})

	// 2. Negative Path: Untrusted Client Cert Rejection
	t.Run("MySQL_mTLS_Untrusted_Cert_Rejection", func(t *testing.T) {
		badCfg := validCfg
		badCfg.ClientCertPath = badCertPath
		badCfg.ClientKeyPath = badKeyPath

		db, _ := database.New("mysql")
		defer func() {
			_ = db.Close()
		}()

		if err := db.Connect(ctx, badCfg, "secretpass"); err == nil {
			if pingErr := db.Ping(ctx); pingErr == nil {
				t.Errorf("Expected MySQL mTLS to reject untrusted client cert, but ping succeeded")
			}
		}
	})

	// 3. Full CLI Scan Verification over mTLS
	t.Run("MySQL_mTLS_CLI_Scan", func(t *testing.T) {
		tempDir := t.TempDir()
		configPath := filepath.Join(tempDir, "mysql_mtls_config.yaml")

		masterKey, _ := libsecsecrets.GenerateKey()
		t.Setenv("DB_SECRET_KEY", masterKey)

		var encOut, encErr bytes.Buffer
		exitCode := dbchecker.RunAppCLI([]string{"-encrypt", "secretpass"}, &encOut, &encErr)
		if exitCode != 0 {
			t.Fatalf("CLI encryption failed: %s", encErr.String())
		}
		encPass := strings.TrimSpace(encOut.String())

		yamlData := fmt.Sprintf(`
databases:
  live_mysql_mtls:
    type: mysql
    host: 127.0.0.1
    port: %d
    user: root
    name: testdb
    password: %s
    tls_mode: verify-full
    root_cert_path: %s
    client_cert_path: %s
    client_key_path: %s
    health_query: "SELECT 1;"
`, portNum, encPass, filepath.ToSlash(caPath), filepath.ToSlash(clientCertPath), filepath.ToSlash(clientKeyPath))

		if err := os.WriteFile(configPath, []byte(yamlData), 0o600); err != nil {
			t.Fatalf("Failed to write yaml config: %v", err)
		}

		var scanOut, scanErr bytes.Buffer
		exitCode = dbchecker.RunAppCLI([]string{"-config", configPath, "-json"}, &scanOut, &scanErr)
		if exitCode != 0 {
			t.Fatalf("CLI mTLS scan failed with exit code %d. Stderr: %s", exitCode, scanErr.String())
		}

		if !strings.Contains(scanOut.String(), "live_mysql_mtls") {
			t.Errorf("Expected scan output to contain live_mysql_mtls, got: %s", scanOut.String())
		}
	})
}

// TestLiveMongoDBMTLS spins up a live MongoDB 8.0 container configured for mTLS (--tlsMode requireTLS) and tests verify-full.
func TestLiveMongoDBMTLS(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping live mTLS tests in -short mode.")
	}
	if !testutil.IsDockerAvailable() {
		t.Skip("Skipping live mTLS tests: Docker daemon not available.")
	}

	testutil.PruneContainers("dbchecker")
	cs := generateLiveMTLSCerts(t)
	localCertDir, mountCertDir := setupLiveMTLSCertDir(t, cs, mongoContainerUIDGID)

	caPath := filepath.Join(localCertDir, "ca.crt")
	clientCertPath := filepath.Join(localCertDir, "client.crt")
	clientKeyPath := filepath.Join(localCertDir, "client.key")
	badCertPath := filepath.Join(localCertDir, "bad_client.crt")
	badKeyPath := filepath.Join(localCertDir, "bad_client.key")

	containerName := fmt.Sprintf("dbchecker-mtls-mongo-%d", time.Now().UnixNano())
	prefix := testutil.GetDockerPrefix()
	_ = exec.Command(prefix[0], append(prefix[1:], "rm", "-f", containerName)...).Run()

	args := append(prefix[1:], "run", "-d", "--name", containerName,
		"-v", fmt.Sprintf("%s:/certs:ro", mountCertDir),
		"-p", "0:27017",
		"mongo:8.0",
		"--tlsMode", "requireTLS",
		"--tlsCAFile", "/certs/ca.crt",
		"--tlsCertificateKeyFile", "/certs/server.pem",
	)

	t.Log("Starting ephemeral MongoDB 8.0 mTLS container...")
	cmd := exec.Command(prefix[0], args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Failed to run mongodb mTLS container: %v. Output: %s", err, string(out))
	}

	t.Cleanup(func() {
		stopArgs := append(prefix[1:], "rm", "-f", containerName)
		_ = exec.Command(prefix[0], stopArgs...).Run()
		if os.Getenv("PRESERVE_DOCKER_IMAGES") != "1" {
			rmiArgs := append(prefix[1:], "rmi", "-f", "mongo:8.0")
			_ = exec.Command(prefix[0], rmiArgs...).Run()
		}
	})

	portArgs := append(append([]string{}, prefix[1:]...), "port", containerName, "27017/tcp")
	portOut, err := exec.Command(prefix[0], portArgs...).CombinedOutput()
	if err != nil {
		portArgs = append(append([]string{}, prefix[1:]...), "port", containerName, "27017")
		portOut, _ = exec.Command(prefix[0], portArgs...).CombinedOutput()
	}
	lines := strings.Split(strings.TrimSpace(string(portOut)), "\n")
	var portNum int
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if idx := strings.LastIndex(line, ":"); idx != -1 {
			if p, err := strconv.Atoi(line[idx+1:]); err == nil && p > 0 {
				portNum = p
				break
			}
		}
	}
	if portNum == 0 {
		t.Fatalf("Failed to parse host port for MongoDB mTLS: %s", string(portOut))
	}
	ctx := context.Background()

	validCfg := config.DatabaseConfig{
		Type:           "mongodb",
		Host:           "127.0.0.1",
		Port:           portNum,
		User:           "",
		Name:           "testdb",
		TLSMode:        "verify-full",
		RootCertPath:   caPath,
		ClientCertPath: clientCertPath,
		ClientKeyPath:  clientKeyPath,
		HealthQuery:    `{"dbStats": 1}`,
	}

	if err := testutil.WaitForDatabase(ctx, "mongodb", validCfg, "", 30*time.Second); err != nil {
		t.Fatalf("MongoDB mTLS container boot timeout: %v", err)
	}

	t.Run("MongoDB_mTLS_Success", func(t *testing.T) {
		mg, err := database.New("mongodb")
		if err != nil {
			t.Fatalf("Failed to instantiate mongodb driver: %v", err)
		}
		if err := mg.Connect(ctx, validCfg, ""); err != nil {
			t.Fatalf("MongoDB mTLS connect failed: %v", err)
		}
		defer func() {
			if closeErr := mg.Close(); closeErr != nil {
				t.Errorf("MongoDB Close failed: %v", closeErr)
			}
		}()

		if err := mg.Ping(ctx); err != nil {
			t.Errorf("MongoDB mTLS ping failed: %v", err)
		}
		if err := mg.HealthCheck(ctx, validCfg.HealthQuery); err != nil {
			t.Errorf("MongoDB mTLS healthcheck failed: %v", err)
		}
	})

	t.Run("MongoDB_mTLS_Untrusted_Cert_Rejection", func(t *testing.T) {
		badCfg := validCfg
		badCfg.ClientCertPath = badCertPath
		badCfg.ClientKeyPath = badKeyPath

		mg, err := database.New("mongodb")
		if err != nil {
			t.Fatalf("Failed to instantiate mongodb driver: %v", err)
		}
		defer func() {
			_ = mg.Close()
		}()

		err = mg.Connect(ctx, badCfg, "")
		if err == nil {
			err = mg.Ping(ctx)
		}
		if err == nil {
			t.Fatal("Expected untrusted client cert connection to fail for MongoDB mTLS, got nil error")
		}
	})
}

// TestLiveOracleWalletMTLSValidation verifies Oracle DB connectivity configuration both without mTLS (disable) and with mTLS (TCPS Wallets).
func TestLiveOracleWalletMTLSValidation(t *testing.T) {
	ctx := context.Background()

	t.Run("Oracle_Without_mTLS_Disable_Mode", func(t *testing.T) {
		ora, err := database.New("oracle")
		if err != nil {
			t.Fatalf("Failed to instantiate Oracle driver: %v", err)
		}
		cfg := config.DatabaseConfig{
			Type:        "oracle",
			Host:        "127.0.0.1",
			Port:        1521,
			User:        "system",
			Name:        "XEPDB1",
			TLSMode:     "disable",
			HealthQuery: "SELECT 1 FROM DUAL",
		}
		if err := ora.Connect(ctx, cfg, "SecretPass2026!"); err != nil {
			t.Fatalf("Oracle Connect (disable TLS) failed: %v", err)
		}
		_ = ora.Close()
	})

	t.Run("Oracle_With_mTLS_TCPS_Wallet_Mode", func(t *testing.T) {
		ora, err := database.New("oracle")
		if err != nil {
			t.Fatalf("Failed to instantiate Oracle driver: %v", err)
		}

		walletDir := t.TempDir()
		_ = os.WriteFile(filepath.Join(walletDir, "cwallet.sso"), []byte("mock_wallet_sso_data"), 0o600)
		_ = os.WriteFile(filepath.Join(walletDir, "ewallet.p12"), []byte("mock_wallet_p12_data"), 0o600)

		cfg := config.DatabaseConfig{
			Type:        "oracle",
			Host:        "127.0.0.1",
			Port:        1522,
			User:        "system",
			Name:        "XEPDB1",
			TLSMode:     "verify-full",
			WalletPath:  walletDir,
			HealthQuery: "SELECT 1 FROM DUAL",
		}
		if err := ora.Connect(ctx, cfg, "SecretPass2026!"); err != nil {
			t.Fatalf("Oracle Connect (TCPS mTLS Wallet) failed: %v", err)
		}
		_ = ora.Close()
	})

	t.Run("Oracle_With_mTLS_Missing_Wallet_Rejection", func(t *testing.T) {
		ora, err := database.New("oracle")
		if err != nil {
			t.Fatalf("Failed to instantiate Oracle driver: %v", err)
		}
		cfg := config.DatabaseConfig{
			Type:        "oracle",
			Host:        "127.0.0.1",
			Port:        1522,
			User:        "system",
			Name:        "XEPDB1",
			TLSMode:     "verify-full",
			WalletPath:  "",
			HealthQuery: "SELECT 1 FROM DUAL",
		}
		err = ora.Connect(ctx, cfg, "SecretPass2026!")
		if err == nil {
			t.Fatal("Expected error when connecting Oracle verify-full without wallet_path, got nil")
		}
		if !strings.Contains(err.Error(), "wallet_path") {
			t.Errorf("Expected wallet_path error message, got: %v", err)
		}
	})
}
