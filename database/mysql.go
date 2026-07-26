package database

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"

	"criticalsys.net/dbchecker/config"
	"github.com/go-sql-driver/mysql"
)

func init() {
	RegisterDriver("mysql", func() DB { return &MySQL{} })
}

var mysqlTLSMutex sync.Mutex

type MySQL struct {
	SQLBase
}

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
		tlsKey := fmt.Sprintf("dbchecker-tls-%s", addr)
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
