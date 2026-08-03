/*
Package database provides a common interface, driver registry, and specific implementations for database drivers.
It abstracts connection management, pinging, and health check execution across SQL and NoSQL engines.
*/
package database

import (
	"context"
	"fmt"
	"sync"

	"github.com/edsilegxrepo/dbchecker/config"
)

// DB defines the standard operations required for any supported database type.
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
