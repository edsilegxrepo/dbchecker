package database

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"

	"github.com/edsilegxrepo/dbchecker/config"
	"github.com/go-sql-driver/mysql"
)

func init() {
	RegisterDriver("mysql", func() DB { return &MySQL{} })
}

// mysqlTLSMutex protects mysql.RegisterTLSConfig which uses a global registry.
var mysqlTLSMutex sync.Mutex

type MySQL struct {
	SQLBase
}

// Connect establishes a MySQL connection with TLS support.
// TLS config registration uses a SHA256 hash of addr+cert paths as the key
// to avoid conflicts when the same host:port uses different certificates.
func (m *MySQL) Connect(ctx context.Context, cfg config.DatabaseConfig, decryptedPassword string) error {
	addr := fmt.Sprintf("%s:%d", cfg.Host, cfg.Port)
	mysqlConfig := mysql.Config{
		User:                 cfg.User,
		Passwd:               decryptedPassword,
		Net:                  "tcp",
		Addr:                 addr,
		DBName:               cfg.Name,
		AllowNativePasswords: true,
	}

	tlsConfig, err := buildTLSConfig(cfg.TLSMode, cfg.Host, cfg.RootCertPath, cfg.ClientCertPath, cfg.ClientKeyPath)
	if err != nil {
		return err
	}

	if tlsConfig != nil {
		// Hash addr+cert paths to create unique TLS config key, avoiding collisions
		// when same host:port has different cert configurations across databases
		h := sha256.New()
		h.Write([]byte(addr))
		h.Write([]byte(cfg.RootCertPath))
		h.Write([]byte(cfg.ClientCertPath))
		h.Write([]byte(cfg.ClientKeyPath))
		tlsKey := fmt.Sprintf("dbchecker-tls-%s", hex.EncodeToString(h.Sum(nil))[:16])
		mysqlTLSMutex.Lock()
		regErr := mysql.RegisterTLSConfig(tlsKey, tlsConfig)
		mysqlTLSMutex.Unlock()
		if regErr != nil && !strings.Contains(regErr.Error(), "already registered") {
			return fmt.Errorf("could not register mysql tls config: %w", regErr)
		}
		mysqlConfig.TLSConfig = tlsKey
	} else {
		mysqlConfig.TLSConfig = "false"
	}

	connectionString := mysqlConfig.FormatDSN()
	db, err := sql.Open("mysql", connectionString)
	if err != nil {
		return err
	}
	m.SetDB(db)
	return nil
}
