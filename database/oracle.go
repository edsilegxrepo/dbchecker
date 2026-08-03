package database

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/edsilegxrepo/dbchecker/config"
	go_ora "github.com/sijms/go-ora/v2"
)

func init() {
	RegisterDriver("oracle", func() DB { return &Oracle{} })
}

type Oracle struct {
	SQLBase
}

func (o *Oracle) Connect(ctx context.Context, cfg config.DatabaseConfig, decryptedPassword string) error {
	urlOptions := make(map[string]string)

	switch cfg.TLSMode {
	case "disable", "":
		// No options needed for non-TLS connection
	case "require":
		urlOptions["ssl"] = "true"
		urlOptions["ssl verify"] = "false"
	case "verify-ca", "verify-full":
		if cfg.WalletPath == "" {
			return fmt.Errorf("tls_mode %q for oracle requires a wallet_path", cfg.TLSMode)
		}
		urlOptions["ssl"] = "true"
		urlOptions["wallet"] = cfg.WalletPath
	default:
		return fmt.Errorf("invalid tls_mode for oracle: %s", cfg.TLSMode)
	}

	connectionString := go_ora.BuildUrl(cfg.Host, cfg.Port, cfg.Name, cfg.User, decryptedPassword, urlOptions)
	db, err := sql.Open("oracle", connectionString)
	if err != nil {
		return err
	}
	o.SetDB(db)
	return nil
}
