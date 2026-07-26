package database

import (
	"context"
	"database/sql"

	"criticalsys.net/dbchecker/config"
	_ "github.com/mattn/go-sqlite3"
)

func init() {
	RegisterDriver("sqlite", func() DB { return &SQLite{} })
}

type SQLite struct {
	SQLBase
}

func (s *SQLite) Connect(ctx context.Context, cfg config.DatabaseConfig, decryptedPassword string) error {
	db, err := sql.Open("sqlite3", cfg.Name)
	if err != nil {
		return err
	}
	s.SetDB(db)
	return nil
}
