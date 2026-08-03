package config

import (
	"net/url"
	"strconv"
	"strings"

	"github.com/go-sql-driver/mysql"
)

// ParseDSN extracts database connection settings and password from a DSN string.
// It supports URL-style DSNs (postgres, sqlserver, mongodb, oracle), MySQL DSNs, and SQLite file DSNs.
func ParseDSN(dsn string) (DatabaseConfig, string, error) {
	if strings.HasPrefix(dsn, "sqlite://") {
		return parseSQLiteDSN(dsn)
	}

	if mysqlCfg, mysqlErr := mysql.ParseDSN(dsn); mysqlErr == nil {
		return parseMySQLDSN(mysqlCfg)
	}

	return parseURLDSN(dsn)
}

func parseSQLiteDSN(dsn string) (DatabaseConfig, string, error) {
	dbName := strings.TrimPrefix(dsn, "sqlite://")
	if strings.HasPrefix(dbName, ":0/file:") {
		dbName = strings.TrimPrefix(dbName, ":0/file:")
	} else if strings.HasPrefix(dbName, "file:") {
		dbName = strings.TrimPrefix(dbName, "file:")
	}
	return DatabaseConfig{
		Type: "sqlite",
		Name: dbName,
	}, "", nil
}

func parseMySQLDSN(mysqlConfig *mysql.Config) (DatabaseConfig, string, error) {
	cfg := DatabaseConfig{
		Type: "mysql",
		User: mysqlConfig.User,
		Name: mysqlConfig.DBName,
	}
	if idx := strings.LastIndex(mysqlConfig.Addr, ":"); idx != -1 {
		cfg.Host = mysqlConfig.Addr[:idx]
		if p, err := strconv.Atoi(mysqlConfig.Addr[idx+1:]); err == nil {
			cfg.Port = p
		}
	} else {
		cfg.Host = mysqlConfig.Addr
	}
	pass := mysqlConfig.Passwd
	if strings.Contains(pass, "%") {
		if unescaped, err := url.PathUnescape(pass); err == nil {
			pass = unescaped
		}
	}
	return cfg, pass, nil
}

func parseURLDSN(dsn string) (DatabaseConfig, string, error) {
	u, err := url.Parse(dsn)
	if err != nil {
		return DatabaseConfig{}, "", err
	}

	dbType := u.Scheme
	if dbType == "postgresql" {
		dbType = "postgres"
	}

	cfg := DatabaseConfig{
		Type: dbType,
		Host: u.Hostname(),
		Name: strings.TrimPrefix(u.Path, "/"),
	}

	if portStr := u.Port(); portStr != "" {
		if p, err := strconv.Atoi(portStr); err == nil {
			cfg.Port = p
		}
	}

	var password string
	if u.User != nil {
		cfg.User = u.User.Username()
		if pass, ok := u.User.Password(); ok {
			password = pass
		}
	}

	switch dbType {
	case "sqlserver":
		if dbName := u.Query().Get("database"); dbName != "" {
			cfg.Name = dbName
		}
		if encrypt := u.Query().Get("encrypt"); encrypt == "disable" || encrypt == "false" {
			cfg.TLSMode = "disable"
		}
	case "mongodb":
		if authSource := u.Query().Get("authSource"); authSource != "" {
			cfg.Name = authSource
		}
	}

	return cfg, password, nil
}
