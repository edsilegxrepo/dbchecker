# Changelog

All notable changes to **DB Connection Diags (`dbchecker`)** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [v1.0.3] - 2026-08-04

### Added
* **DecryptBytes for Memory Hygiene**: Added `crypto.DecryptBytes()` returning `[]byte` instead of `string`, enabling password buffer zeroing via `crypto.ZeroBuffer()` after use. Passwords in Go strings cannot be zeroed from memory.
* **Deterministic Result Ordering**: `CheckAll()` now returns results sorted alphabetically by database ID for reproducible output across runs (Go map iteration is random).
* **JSON Serialization Fixes**: Added `DurationMs` (int64 milliseconds) and `ErrorMsg` (string) fields to `Result` struct. Raw `Duration` (nanoseconds) and `Err` (empty object `{}`) are excluded from JSON via `json:"-"` tags.
* **Comprehensive Test Coverage**: Added 15+ new unit tests covering all TLS modes, DSN parsing edge cases, and driver lifecycle for MySQL, PostgreSQL, SQLite, MongoDB, SQL Server, and Oracle. Core package coverage now at **91.6%**.
* **Test Runner Script**: Added `test/run_tests.sh` for convenient test execution with optional `--integration` flag.

### Changed
* **Documentation Updates**: Revised `README.md`, `ARCHITECTURE.md`, `DESIGN.md`, and `TESTING.md` to reflect new `DecryptBytes` usage, deterministic ordering, corrected JSON output examples, and updated coverage statistics.

### Fixed
* **MongoDB Close Timeout**: `MongoDB.Close()` now uses a 5-second timeout context instead of unbounded `context.Background()` to prevent indefinite blocking.
* **MySQL TLS Config Key Collision**: TLS config registry key now includes SHA256 hash of cert paths, avoiding conflicts when same host:port uses different certificates.

---

## [v1.0.2] - 2026-07-29

### Added
* **Modular Integration Test Package (`test/`)**: Reorganized test infrastructure by moving long-running live container integration test suites (`live_docker_test.go`, `live_e2e_test.go`, `live_mtls_test.go`) into dedicated `test/` package with `//go:build integration` build tags, enabling instant (<1s) unit test execution (`go test ./...`).
* **Reusable Test Utility Module (`testutil`)**: Extracted shared container orchestration routines (`StartLiveDatabaseCluster`, `WaitForDatabase`, `PruneContainers`, `GetDockerPrefix`, `IsDockerAvailable`, `RunEphemeralContainer`) into decoupled helper module `criticalsys.net/dbchecker/testutil`.
* **Universal DSN Parser & Test Suite (`config/dsn.go`)**: Implemented robust `ParseDSN` helper functions with complete support for special characters (`@`, `:`, `/`, `%`, `?`, `#`) in passwords and query parameter extraction across PostgreSQL, MySQL, SQLite, MongoDB, MSSQL, and Oracle drivers.

---

## [v1.0.1] - 2026-07-27

### Added
* **Parallel Ephemeral Container Launcher**: Refactored `TestLiveDockerContainers` to launch and poll all 5 database engine containers (**PostgreSQL 18**, **MySQL 8.4**, **MongoDB 8.0**, **MSSQL / Azure SQL Edge**, and **Oracle 21c Slim**) concurrently across 5 parallel goroutines using `sync.WaitGroup`, reducing test execution time by 67%.
* **Live mTLS Verification Suite**: Added live mTLS integration testing for **PostgreSQL 18** (`-c ssl=on`), **MySQL 8.4** (`--require-secure-transport=ON`), **MongoDB 8.0** (`--tlsMode requireTLS`), and **Oracle 21c** (`verify-full` with TCPS Oracle Wallets).
* **POSIX Ownership & Secure Permissions**: Implemented symmetric container user ownership (`chown -R <uid:gid>`) and strict permission enforcement (`chmod 0755` directory, `0644` certificates, `0600` private keys) across Windows (WSL) and Linux native environments.
* **Pre-Test Container Teardown (`pruneDbcheckerContainers`)**: Enforced automatic force-cleaning (`docker rm -f dbchecker*`) before tests start to prevent host container clutter and duplicate naming collisions.
* **Oracle TCPS Wallet Validation**: Added `TestLiveOracleWalletMTLSValidation` verifying Oracle Wallet loading (`cwallet.sso`), DSN parameter formatting (`ssl=true&wallet=<path>`), and missing wallet rejection.

### Fixed
* **SQL Server TLS Mode**: Set `query.Add("encrypt", "disable")` for disabled/empty TLS modes in `database/sqlserver.go`, resolving Go 1.23+ `crypto/x509` negative serial number validation errors when connecting to `azure-sql-edge` containers.
* **Linter Quality & Code Hygiene**: Resolved all `errcheck` linter warnings for `db.Close()` and `mg.Close()` in `live_docker_test.go` and `live_mtls_test.go`, achieving `STATUS: [PASSED] ALL CONTROLS COMPLIANT` on DevOps `code_audit.sh`.

---

## [v1.0.0] - 2026-07-25

### Added
* **SecretProtector Integration**: Replaced legacy crypto implementation with `criticalsys/secretprotector/pkg/libsecsecrets` for envelope encryption, key resolution, and RAM buffer zeroing (`ZeroMemoryBuffer`).
* **Granular CLI Exit Codes**: Implemented standardized exit codes (0 = Success, 1 = Config Error, 2 = Key Error, 3 = Decryption Error, 4 = Connection Error, 5 = Health Check Error).
* **Comprehensive Documentation Suite**: Authored detailed architectural design docs (`ARCHITECTURE.md`) and testing pyramid documentation (`TESTING.md`).
* **JSON Diagnostic Output**: Added `-json` CLI output flag for structured diagnostic reporting in automated monitoring systems.

---

## [v0.9.0] - 2025-08-28

### Added
* **mTLS & Granular TLS Modes**: Added support for `disable`, `require`, `verify-ca`, and `verify-full` TLS modes across PostgreSQL, MySQL, MongoDB, and SQL Server drivers.
* **Custom Root CA & Client Certificate Scoping**: Integrated `readScopedFile` using `os.OpenRoot` for secure certificate loading.
* **Robust DSN Builders**: Refactored database connection string logic into isolated driver factory modules.

---

## [v0.8.0] - 2025-08-27

### Added
* **CLI Password Encryption (`-encrypt`)**: Introduced `-encrypt` flag for generating encrypted password ciphertexts via CLI.
* **Secret Key File Support (`-key-file`)**: Added ability to load master secret key material from disk files with `0600` permission checks.
* **Application Restructure**: Modularized application codebase into `config`, `crypto`, `database`, `pkg/dbchecker`, and `cmd/dbchecker`.

---

## [v0.1.0] - 2025-01-30

### Added
* **Initial Release**: Initial implementation of DB Connection Diags (`dbchecker`) supporting basic connection health checking for relational and document database engines.
