package config_test

import (
	"fmt"
	"net/url"
	"testing"

	"github.com/edsilegxrepo/dbchecker/config"
)

func TestParseDSN_PostgreSQL(t *testing.T) {
	dsn := "postgres://pguser:pgpass@127.0.0.1:5432/healthtest?sslmode=disable"
	cfg, pass, err := config.ParseDSN(dsn)
	if err != nil {
		t.Fatalf("ParseDSN failed for postgres: %v", err)
	}

	if cfg.Type != "postgres" {
		t.Errorf("Expected type 'postgres', got %q", cfg.Type)
	}
	if cfg.Host != "127.0.0.1" {
		t.Errorf("Expected host '127.0.0.1', got %q", cfg.Host)
	}
	if cfg.Port != 5432 {
		t.Errorf("Expected port 5432, got %d", cfg.Port)
	}
	if cfg.User != "pguser" {
		t.Errorf("Expected user 'pguser', got %q", cfg.User)
	}
	if pass != "pgpass" {
		t.Errorf("Expected password 'pgpass', got %q", pass)
	}
	if cfg.Name != "healthtest" {
		t.Errorf("Expected db name 'healthtest', got %q", cfg.Name)
	}
}

func TestParseDSN_MySQL(t *testing.T) {
	dsn := "root:secretpass@tcp(127.0.0.1:3306)/mysqltest"
	cfg, pass, err := config.ParseDSN(dsn)
	if err != nil {
		t.Fatalf("ParseDSN failed for mysql: %v", err)
	}

	if cfg.Type != "mysql" {
		t.Errorf("Expected type 'mysql', got %q", cfg.Type)
	}
	if cfg.Host != "127.0.0.1" {
		t.Errorf("Expected host '127.0.0.1', got %q", cfg.Host)
	}
	if cfg.Port != 3306 {
		t.Errorf("Expected port 3306, got %d", cfg.Port)
	}
	if cfg.User != "root" {
		t.Errorf("Expected user 'root', got %q", cfg.User)
	}
	if pass != "secretpass" {
		t.Errorf("Expected password 'secretpass', got %q", pass)
	}
	if cfg.Name != "mysqltest" {
		t.Errorf("Expected db name 'mysqltest', got %q", cfg.Name)
	}
}

func TestParseDSN_SQLite(t *testing.T) {
	dsn := "sqlite://:0/file:/var/data/sqlite.db"
	cfg, pass, err := config.ParseDSN(dsn)
	if err != nil {
		t.Fatalf("ParseDSN failed for sqlite: %v", err)
	}

	if cfg.Type != "sqlite" {
		t.Errorf("Expected type 'sqlite', got %q", cfg.Type)
	}
	if pass != "" {
		t.Errorf("Expected empty password for sqlite, got %q", pass)
	}
	if cfg.Name != "/var/data/sqlite.db" {
		t.Errorf("Expected db name '/var/data/sqlite.db', got %q", cfg.Name)
	}
}

func TestParseDSN_MongoDB(t *testing.T) {
	dsn := "mongodb://mongouser:mongopass@127.0.0.1:27017/appdb?authSource=admin"
	cfg, pass, err := config.ParseDSN(dsn)
	if err != nil {
		t.Fatalf("ParseDSN failed for mongodb: %v", err)
	}

	if cfg.Type != "mongodb" {
		t.Errorf("Expected type 'mongodb', got %q", cfg.Type)
	}
	if cfg.Host != "127.0.0.1" {
		t.Errorf("Expected host '127.0.0.1', got %q", cfg.Host)
	}
	if cfg.Port != 27017 {
		t.Errorf("Expected port 27017, got %d", cfg.Port)
	}
	if cfg.User != "mongouser" {
		t.Errorf("Expected user 'mongouser', got %q", cfg.User)
	}
	if pass != "mongopass" {
		t.Errorf("Expected password 'mongopass', got %q", pass)
	}
	if cfg.Name != "admin" {
		t.Errorf("Expected db authSource name 'admin', got %q", cfg.Name)
	}
}

func TestParseDSN_MSSQL(t *testing.T) {
	dsn := "sqlserver://sa:SecretPass2026!@127.0.0.1:1433?database=master&encrypt=disable"
	cfg, pass, err := config.ParseDSN(dsn)
	if err != nil {
		t.Fatalf("ParseDSN failed for sqlserver: %v", err)
	}

	if cfg.Type != "sqlserver" {
		t.Errorf("Expected type 'sqlserver', got %q", cfg.Type)
	}
	if cfg.Host != "127.0.0.1" {
		t.Errorf("Expected host '127.0.0.1', got %q", cfg.Host)
	}
	if cfg.Port != 1433 {
		t.Errorf("Expected port 1433, got %d", cfg.Port)
	}
	if cfg.User != "sa" {
		t.Errorf("Expected user 'sa', got %q", cfg.User)
	}
	if pass != "SecretPass2026!" {
		t.Errorf("Expected password 'SecretPass2026!', got %q", pass)
	}
	if cfg.Name != "master" {
		t.Errorf("Expected db name 'master', got %q", cfg.Name)
	}
	if cfg.TLSMode != "disable" {
		t.Errorf("Expected tls_mode 'disable', got %q", cfg.TLSMode)
	}
}

func TestParseDSN_Oracle(t *testing.T) {
	dsn := "oracle://system:OraclePass!@127.0.0.1:1521/XEPDB1"
	cfg, pass, err := config.ParseDSN(dsn)
	if err != nil {
		t.Fatalf("ParseDSN failed for oracle: %v", err)
	}

	if cfg.Type != "oracle" {
		t.Errorf("Expected type 'oracle', got %q", cfg.Type)
	}
	if cfg.Host != "127.0.0.1" {
		t.Errorf("Expected host '127.0.0.1', got %q", cfg.Host)
	}
	if cfg.Port != 1521 {
		t.Errorf("Expected port 1521, got %d", cfg.Port)
	}
	if cfg.User != "system" {
		t.Errorf("Expected user 'system', got %q", cfg.User)
	}
	if pass != "OraclePass!" {
		t.Errorf("Expected password 'OraclePass!', got %q", pass)
	}
	if cfg.Name != "XEPDB1" {
		t.Errorf("Expected db name 'XEPDB1', got %q", cfg.Name)
	}
}

func TestParseDSN_SpecialCharacters(t *testing.T) {
	// Base64 encrypted password containing + and =
	base64Pass := "24dQqG2a+CWMXc9Fb9Ek9B6oUuoc32exkUryLqgE66lCkCfuwZA="

	mysqlDSN := "root:" + base64Pass + "@tcp(127.0.0.1:3306)/testdb"
	_, pass, err := config.ParseDSN(mysqlDSN)
	if err != nil {
		t.Fatalf("ParseDSN failed for MySQL base64 password: %v", err)
	}
	if pass != base64Pass {
		t.Errorf("Expected MySQL password %q, got %q", base64Pass, pass)
	}

	// Percent-encoded special characters: P@ss+w#rd! -> P%40ss%2Bw%23rd%21
	encodedPass := "P%40ss%2Bw%23rd%21"
	expectedDecoded := "P@ss+w#rd!"

	pgDSN := "postgres://user:" + encodedPass + "@127.0.0.1:5432/testdb"
	_, pass, err = config.ParseDSN(pgDSN)
	if err != nil {
		t.Fatalf("ParseDSN failed for Postgres percent-encoded password: %v", err)
	}
	if pass != expectedDecoded {
		t.Errorf("Expected Postgres password %q, got %q", expectedDecoded, pass)
	}
}

func TestParseDSN_AllSpecialCharacters(t *testing.T) {
	// All printable ASCII special characters
	allSpecialCharsPass := `!"#$%&'()*+,-./:;<=>?@[\]^_` + "`" + `{|}~`
	escapedPass := url.PathEscape(allSpecialCharsPass)

	tests := []struct {
		name string
		dsn  string
	}{
		{
			name: "PostgreSQL",
			dsn:  fmt.Sprintf("postgres://user:%s@127.0.0.1:5432/testdb", escapedPass),
		},
		{
			name: "MySQL",
			dsn:  fmt.Sprintf("user:%s@tcp(127.0.0.1:3306)/testdb", escapedPass),
		},
		{
			name: "MongoDB",
			dsn:  fmt.Sprintf("mongodb://user:%s@127.0.0.1:27017/testdb?authSource=admin", escapedPass),
		},
		{
			name: "MSSQL",
			dsn:  fmt.Sprintf("sqlserver://user:%s@127.0.0.1:1433?database=master", escapedPass),
		},
		{
			name: "Oracle",
			dsn:  fmt.Sprintf("oracle://user:%s@127.0.0.1:1521/XEPDB1", escapedPass),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, parsedPass, err := config.ParseDSN(tt.dsn)
			if err != nil {
				t.Fatalf("ParseDSN failed for %s with all special chars: %v", tt.name, err)
			}
			if parsedPass != allSpecialCharsPass {
				t.Errorf("Password corruption for %s:\nExpected: %q\nGot:      %q", tt.name, allSpecialCharsPass, parsedPass)
			}
		})
	}
}
