/*
Package database provides a common interface, driver registry, and specific implementations for database drivers.
It abstracts connection management, pinging, and health check execution across SQL and NoSQL engines.

Supported Drivers (registered via init()):
  - postgres: PostgreSQL via lib/pq
  - mysql: MySQL via go-sql-driver/mysql
  - sqlite: SQLite via mattn/go-sqlite3
  - sqlserver: SQL Server via microsoft/go-mssqldb
  - oracle: Oracle via sijms/go-ora
  - mongodb: MongoDB via mongo-driver/v2

Architecture:
  - DB interface: Connect, Ping, HealthCheck, Close
  - SQLBase: Shared implementation for SQL drivers (SetDB, Ping, HealthCheck, Close)
  - Driver registry: Thread-safe map with init()-time registration
*/
package database

import (
	"context"
	"fmt"
	"sync"

	"github.com/edsilegxrepo/dbchecker/config"
)

// DB defines the standard operations required for any supported database type.
// Note: The ctx parameter in Connect is reserved for future use with context-aware
// database connectors (e.g., sql.OpenDB with pgx). Currently, sql.Open() does not
// support context cancellation - the actual connection is established lazily on
// first query. Callers should use ctx in Ping/HealthCheck to enforce timeouts.
type DB interface {
	Connect(ctx context.Context, cfg config.DatabaseConfig, decryptedPassword string) error
	Ping(ctx context.Context) error
	HealthCheck(ctx context.Context, query string) error
	Close() error
}

// DriverFactory is a constructor function that returns a new DB instance.
type DriverFactory func() DB

var (
	registryMu sync.RWMutex
	registry   = make(map[string]DriverFactory)
)

// RegisterDriver registers a database driver factory for a given database type name.
// Driver implementations call this in their init() functions.
func RegisterDriver(name string, factory DriverFactory) {
	registryMu.Lock()
	defer registryMu.Unlock()
	if factory == nil {
		panic("database: RegisterDriver factory is nil")
	}
	registry[name] = factory
}

// IsSupported returns true if the specified database type has been registered.
func IsSupported(dbType string) bool {
	registryMu.RLock()
	defer registryMu.RUnlock()
	_, ok := registry[dbType]
	return ok
}

// New is a factory function that returns an implementation of the DB interface
// based on the registered database type string.
func New(dbType string) (DB, error) {
	registryMu.RLock()
	factory, ok := registry[dbType]
	registryMu.RUnlock()

	if !ok {
		return nil, fmt.Errorf("unsupported database type: %s", dbType)
	}
	return factory(), nil
}
