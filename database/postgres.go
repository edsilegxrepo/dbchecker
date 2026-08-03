package database

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strings"

	"github.com/edsilegxrepo/dbchecker/config"
	_ "github.com/lib/pq"
)

func init() {
	RegisterDriver("postgres", func() DB { return &Postgres{} })
}

type Postgres struct {
	SQLBase
}

func (p *Postgres) Connect(ctx context.Context, cfg config.DatabaseConfig, decryptedPassword string) error {
	dbName := cfg.Name
	if dbName != "" && !strings.HasPrefix(dbName, "/") {
		dbName = "/" + dbName
	}

	dsn := url.URL{
		Scheme: "postgres",
		User:   url.UserPassword(cfg.User, decryptedPassword),
		Host:   fmt.Sprintf("%s:%d", cfg.Host, cfg.Port),
		Path:   dbName,
	}

	query := dsn.Query()
	var sslMode string
	switch cfg.TLSMode {
	case "require":
		sslMode = "require"
	case "verify-ca":
		sslMode = "verify-ca"
	case "verify-full":
		sslMode = "verify-full"
	case "disable", "": // Treat empty as disable
		sslMode = "disable"
	default:
		return fmt.Errorf("invalid tls_mode for postgres: %s", cfg.TLSMode)
	}
	query.Set("sslmode", sslMode)

	if cfg.RootCertPath != "" {
		query.Set("sslrootcert", cfg.RootCertPath)
	}
	if cfg.ClientCertPath != "" {
		query.Set("sslcert", cfg.ClientCertPath)
	}
	if cfg.ClientKeyPath != "" {
		query.Set("sslkey", cfg.ClientKeyPath)
	}

	dsn.RawQuery = query.Encode()

	db, err := sql.Open("postgres", dsn.String())
	if err != nil {
		return err
	}
	p.SetDB(db)
	return nil
}
