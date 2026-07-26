package database

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"
)

// SQLBase provides shared ping, query execution, connection limits, and close logic for SQL drivers.
type SQLBase struct {
	db *sql.DB
}

// SetDB assigns the underlying sql.DB instance and configures optimal diagnostic connection limits.
func (b *SQLBase) SetDB(db *sql.DB) {
	b.db = db
	if b.db != nil {
		b.db.SetMaxOpenConns(1)
		b.db.SetMaxIdleConns(1)
		b.db.SetConnMaxLifetime(30 * time.Second)
	}
}

func (b *SQLBase) Ping(ctx context.Context) error {
	if b.db == nil {
		return errors.New("database connection not initialized")
	}
	return b.db.PingContext(ctx)
}

func (b *SQLBase) HealthCheck(ctx context.Context, query string) error {
	if b.db == nil {
		return errors.New("database connection not initialized")
	}
	rows, err := b.db.QueryContext(ctx, query)
	if err != nil {
		return fmt.Errorf("health check query failed: %w", err)
	}
	defer func() {
		_ = rows.Close()
	}()
	return nil
}

func (b *SQLBase) Close() error {
	if b.db == nil {
		return nil
	}
	return b.db.Close()
}
