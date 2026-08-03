package database

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"

	"github.com/edsilegxrepo/dbchecker/config"
	_ "github.com/microsoft/go-mssqldb"
)

func init() {
	RegisterDriver("sqlserver", func() DB { return &SQLServer{} })
}

type SQLServer struct {
	SQLBase
}

func (s *SQLServer) Connect(ctx context.Context, cfg config.DatabaseConfig, decryptedPassword string) error {
	query := url.Values{}
	query.Add("database", cfg.Name)

	switch cfg.TLSMode {
	case "disable", "":
		query.Add("encrypt", "disable")
		query.Add("TrustServerCertificate", "true")
	case "require":
		query.Add("encrypt", "true")
		query.Add("TrustServerCertificate", "true")
	case "verify-ca", "verify-full":
		query.Add("encrypt", "true")
		query.Add("TrustServerCertificate", "false")
	default:
		return fmt.Errorf("invalid tls_mode for sqlserver: %s", cfg.TLSMode)
	}

	if cfg.RootCertPath != "" {
		query.Add("certificate", cfg.RootCertPath)
	}

	dsn := &url.URL{
		Scheme:   "sqlserver",
		User:     url.UserPassword(cfg.User, decryptedPassword),
		Host:     fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		RawQuery: query.Encode(),
	}

	db, err := sql.Open("sqlserver", dsn.String())
	if err != nil {
		return err
	}
	s.SetDB(db)
	return nil
}
