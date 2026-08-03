# DB Connection Diags (`dbchecker`)

[![Go Version](https://img.shields.io/badge/Go-1.24%2B-00ADD8?style=flat&logo=go)](https://golang.org)
[![Coverage](https://img.shields.io/badge/Coverage-88.1%25-brightgreen?style=flat)](./TESTING.md)
[![Architecture](https://img.shields.io/badge/Architecture-Modular%20Library%20%2B%20CLI-blue?style=flat)](./ARCHITECTURE.md)

`dbchecker` is an enterprise-grade Go library and CLI utility designed to diagnose, profile, and verify multi-database connectivity across heterogeneous SQL and NoSQL database engines (**MySQL**, **PostgreSQL**, **MongoDB v2**, **Oracle**, **SQL Server**, and **SQLite**).

It features **AES-256-GCM envelope encryption** via `secretprotector`, **Go 1.24+ `os.OpenRoot` directory handle scoping** for file access defense, **TLS/mTLS authentication**, and a **Least-Privilege operating model requiring zero administrative privileges**.

---

## Quick Links
* [Architecture & Design Specifications (`ARCHITECTURE.md`)](./ARCHITECTURE.md)
* [Test Suite Architecture & Quality Assurance (`TESTING.md`)](./TESTING.md)

---

## 1. Application Overview and Objectives

`dbchecker` provides a dual-layer solution for database health monitoring:
1. **Importable Go Library (`pkg/dbchecker`)**: Programmatic API for integration into backend microservices, API Gateways, and HTTP health servers (such as `health-checker`), returning strongly-typed `Result` diagnostic objects with latency timing and step error categorization.
2. **CLI Executable (`cmd/dbchecker`)**: Command-line tool for system administrators, DevOps engineers, and container sidecars to run batch database checks and format results as human-readable text or structured JSON.

### Primary Objectives
- **Multi-Engine Health Verification**: Standardize connection initialization, ping handshakes, and healthcheck query execution across 6 database engines.
- **Credential Protection**: Prevent plaintext passwords from residing on disk using authenticated AES-256-GCM encryption.
- **Directory Traversal Defense**: Enforce strict directory scoping using Go 1.24+ `os.OpenRoot` for YAML configs, TLS Root CAs, and mTLS keypairs.
- **High Concurrency & Low Overhead**: Execute concurrent checks using bounded goroutine worker pools with minimal CPU and memory footprints.
- **Least-Privilege Operation**: Guarantee that diagnostic checks execute without requiring administrative or DBA database account permissions.

---

## 2. Security Assessment

`dbchecker` underwent rigorous security engineering to ensure zero-trust compliance across all execution paths:

### A. Encryption in Transit (TLS / mTLS)
- **Supported Modes**: `disable`, `require` (TLS skip verify), `verify-ca` (CA certificate check), and `verify-full` (CA check + hostname verification).
- **Custom Certificate Authorities**: Scoped loading of custom Root CAs (`root_cert_path`) via Go 1.24 `os.OpenRoot`.
- **Mutual TLS (mTLS)**: Scoped loading of client certificate/key pairs (`client_cert_path`, `client_key_path`).
- **Oracle Wallets**: Native support for encrypted Oracle Wallet directories (`wallet_path`).

### B. Secret Management & Memory Hygiene
- **Cryptographic Subsystem**: Integrates with `criticalsys/secretprotector/pkg/libsecsecrets` for AES-256-GCM authenticated encryption (`nonce + ciphertext + tag`).
- **Key Resolution Hierarchy**: Resolves 32-byte master keys with strict precedence (`raw` flag > `DB_SECRET_KEY` env var > `-key-file` path).
- **RAM Hygiene**: Master secret key byte buffers are zeroed out in memory immediately after resolution using `crypto.ZeroBuffer`.
- **Key File Permissions**: Validates strict OS file permissions (`0400`/`0600` on Linux/macOS; restricted ACLs on Windows) and rejects insecure `/temp/` directory locations.

### C. Authentication Configuration & RBAC (Least-Privilege Model)
- **Zero Administrative Privileges**: `dbchecker` operates strictly under **Least Privilege**. No `root`, `superuser`, `DBA`, `sysadmin`, or `db_owner` permissions are required.
- **Required Account Privileges per Engine**:
  - **MySQL**: `USAGE` privilege (the baseline user permission).
  - **PostgreSQL**: `CONNECT` privilege on the target database.
  - **MongoDB v2**: `read` role (or `listCollections` & `dbStats` actions).
  - **Oracle**: `CREATE SESSION` system privilege.
  - **SQL Server**: `CONNECT SQL` permission (`public` role).
  - **SQLite**: Read/Write OS filesystem permissions on the `.sqlite` file.

### D. Modern, Non-Vulnerable Dependency Stack
- **Go Runtime**: Go 1.24+ with strict `os.OpenRoot` handle isolation.
- **Security Dependency**: `criticalsys/secretprotector` (`secretprotector` CLI & `libsecsecrets` library for AES-256-GCM encryption and CSPRNG key generation).
- **Driver Stack**:
  - `github.com/go-sql-driver/mysql`
  - `github.com/lib/pq`
  - `go.mongodb.org/mongo-driver/v2` (Official MongoDB v2 driver)
  - `github.com/sijms/go-ora/v2`
  - `github.com/microsoft/go-mssqldb`
  - `github.com/mattn/go-sqlite3`

### E. Unprivileged Execution Context
- `dbchecker` runs as an unprivileged, non-system process under standard OS user accounts. It requires no root/administrator privileges, no system daemon installation, and no raw socket network capabilities.

---

## 3. Code Quality Assessment and Best Practices

- **Test Coverage**: Maintains **88.1% total repository statement coverage** (**100.0%** in `crypto`, **93.1%** in `pkg/dbchecker`, **92.6%** in `config`). Every package exceeds the required 80.0% quality gate.
- **Modular Plugin Architecture**: Self-registering thread-safe driver registry (`sync.RWMutex`) decouples database engines from core application logic.
- **Structured Error Handling**: Returns typed error step constants (`StepDecryption`, `StepDriverInit`, `StepConnect`, `StepPing`, `StepHealthCheck`) and granular exit codes (0 to 5).
- **Context Awareness**: Propagates `context.Context` deadlines through all network handshakes, query executions, and driver calls.

---

## 4. Command-Line Arguments & Granular Exit Codes

The `cmd/dbchecker` binary accepts the following CLI flags:

| Flag Name | Argument Type | Default Value | Description |
| :--- | :---: | :---: | :--- |
| `-config` | `string` | `"config.yaml"` | Path to the YAML database configuration file. |
| `-db` | `string` | `""` (All) | Identifier of a specific database to check. If omitted, checks all databases in config. |
| `-version` | `bool` | `false` | Displays application version details and exits. |
| `-encrypt` | `string` | `""` | Encrypts a plaintext password string using the secret key and outputs Base64 result. |
| `-key-file` | `string` | `""` | Path to secret key file (overrides `DB_SECRET_KEY` environment variable). |
| `-timeout` | `duration` | `10s` | Maximum connection and check timeout per database (e.g. `5s`, `2s`). |
| `-concurrency` | `int` | `10` | Maximum number of concurrent database check worker routines. |
| `-json` | `bool` | `false` | Formats diagnostic results as a structured JSON array for machine parsing. |

### Granular Diagnostic Exit Codes

For integration into automated CI/CD pipelines, container sidecars, and Kubernetes probes, `dbchecker` returns granular process exit codes:

| Exit Code | Constant Name | Description |
| :---: | :--- | :--- |
| `0` | `ExitSuccess` | All database connectivity and health checks passed successfully. |
| `1` | `ExitConfigError` | Configuration file loading error, malformed YAML syntax, or invalid CLI flag. |
| `2` | `ExitKeyError` | Master secret key resolution failure or OS file permission violation. |
| `3` | `ExitDecryptionError` | Password decryption failure (corrupt ciphertext or incorrect master key). |
| `4` | `ExitConnectionError` | TCP socket connection drop or network dial timeout. |
| `5` | `ExitHealthError` | Database ping failure or custom healthcheck query execution error. |

---

## 5. Configuration Schema and Reference

The application reads database configurations from a YAML file (default `config.yaml`):

```yaml
databases:
  <database-id>:
    type: "mysql | postgres | mongodb | oracle | sqlserver | sqlite"
    host: "string"
    port: int
    user: "string"
    password: "string (Base64 AES-GCM Encrypted)"
    name: "string (Database or Schema name, or SQLite file path)"
    tls_mode: "disable | require | verify-ca | verify-full"
    wallet_path: "string (Optional, Oracle Wallet directory path)"
    root_cert_path: "string (Optional, Path to custom PEM Root CA)"
    client_cert_path: "string (Optional, Path to mTLS client cert PEM)"
    client_key_path: "string (Optional, Path to mTLS client key PEM)"
    health_query: "string (Optional, SQL query string or MongoDB JSON command)"
```

### Configuration Field Reference

- `<database-id>`: Unique string identifier for the database target.
- `type`: Database engine driver string (`mysql`, `postgres`, `mongodb`, `oracle`, `sqlserver`, `sqlite`).
- `host`: Hostname or IP address of the database server.
- `port`: TCP port number (e.g., `3306` for MySQL, `5432` for Postgres, `27017` for Mongo, `1521` for Oracle, `1433` for SQL Server).
- `user`: Database account username.
- `password`: Base64 AES-256-GCM encrypted password string.
- `name`: Target database/schema name (or file path for SQLite).
- `tls_mode`: TLS transport mode:
  - `disable`: Standard unencrypted connection.
  - `require`: TLS enabled, skip CA verification.
  - `verify-ca`: TLS enabled, verify server certificate against CA.
  - `verify-full`: TLS enabled, verify CA certificate and hostname match.
- `wallet_path`: Path to Oracle Wallet directory (required for Oracle `verify-ca`/`verify-full`).
- `root_cert_path`: Path to custom Root CA PEM certificate file.
- `client_cert_path`: Path to mTLS client certificate PEM file.
- `client_key_path`: Path to mTLS client private key PEM file.
- `health_query`: Custom SQL query (e.g. `SELECT 1;` or `SELECT 1 FROM DUAL;`) or MongoDB JSON command (e.g. `{"dbStats": 1}`).

---

## 6. Usage & Deployment Examples

### Step 1: Encrypting Database Passwords

**Generate a 32-Byte Master Key File using `secretprotector` CLI**:
```bash
# On Linux / macOS:
secretprotector -generate > /etc/dbchecker/master.key
chmod 400 /etc/dbchecker/master.key

# On Windows (PowerShell):
secretprotector -generate > C:\dbchecker\master.key
icacls "C:\dbchecker\master.key" /inheritance:r
icacls "C:\dbchecker\master.key" /grant:r "$($env:USERNAME):(R)"
```

**Encrypt Plaintext Password**:
Using `secretprotector` CLI or `dbchecker`:
```bash
secretprotector -encrypt "MySuperSecretPass2026!" -key-file /etc/dbchecker/master.key
# OR using dbchecker CLI:
./dbchecker -key-file /etc/dbchecker/master.key -encrypt "MySuperSecretPass2026!"
```
*Output*:
```text
v1:U2FsdGVkX19...Base64EncryptedCiphertextHere...
```

---

### Step 2: Creating `config.yaml` (All 6 Database Engines Covered)

```yaml
databases:
  mysql_orders:
    type: mysql
    host: mysql.internal.company.com
    port: 3306
    user: mon_user
    password: "v1:U2FsdGVkX19...Base64EncryptedCiphertextHere..."
    name: orders_db
    tls_mode: verify-full
    health_query: "SELECT 1;"

  pg_production:
    type: postgres
    host: pg.internal.company.com
    port: 5432
    user: db_mon
    password: "v1:U2FsdGVkX19...Base64EncryptedCiphertextHere..."
    name: prod_db
    tls_mode: verify-full
    health_query: "SELECT 1;"

  mongo_cluster:
    type: mongodb
    host: mongo.internal.company.com
    port: 27017
    user: mon_user
    password: "v1:U2FsdGVkX19...Base64EncryptedCiphertextHere..."
    name: admin
    tls_mode: verify-ca
    health_query: '{"dbStats": 1}'

  oracle_finance:
    type: oracle
    host: ora.internal.company.com
    port: 1521
    user: ora_mon
    password: "v1:U2FsdGVkX19...Base64EncryptedCiphertextHere..."
    name: FINPRD
    tls_mode: verify-ca
    wallet_path: "/etc/oracle/wallets/finance"
    health_query: "SELECT 1 FROM DUAL;"

  sqlserver_erp:
    type: sqlserver
    host: mssql.internal.company.com
    port: 1433
    user: erp_mon
    password: "v1:U2FsdGVkX19...Base64EncryptedCiphertextHere..."
    name: ERP_PROD
    tls_mode: verify-ca
    root_cert_path: "/etc/ssl/certs/mssql-ca.crt"
    health_query: "SELECT 1;"

  sqlite_local:
    type: sqlite
    name: "/var/data/app.db"
    health_query: "SELECT 1;"
```

---

### Step 3: Running Diagnostic Checks

#### Standard Text Console Output (All 6 Engines)
```bash
./dbchecker -key-file /etc/dbchecker/master.key -config config.yaml
```
*Sample Output*:
```text
Successfully connected and checked mysql_orders (mysql) [12.4ms]
Successfully connected and checked pg_production (postgres) [14.2ms]
Successfully connected and checked mongo_cluster (mongodb) [22.8ms]
Successfully connected and checked oracle_finance (oracle) [35.1ms]
Successfully connected and checked sqlserver_erp (sqlserver) [18.6ms]
Successfully connected and checked sqlite_local (sqlite) [0.4ms]
```

#### JSON Output Formatting (`-json`)
```bash
./dbchecker -key-file /etc/dbchecker/master.key -config config.yaml -json
```
*Sample Output*:
```json
[
  {
    "id": "mysql_orders",
    "type": "mysql",
    "success": true,
    "exit_code": 0,
    "duration_ms": 12400000
  },
  {
    "id": "pg_production",
    "type": "postgres",
    "success": true,
    "exit_code": 0,
    "duration_ms": 14200000
  },
  {
    "id": "mongo_cluster",
    "type": "mongodb",
    "success": true,
    "exit_code": 0,
    "duration_ms": 22800000
  },
  {
    "id": "oracle_finance",
    "type": "oracle",
    "success": true,
    "exit_code": 0,
    "duration_ms": 35100000
  },
  {
    "id": "sqlserver_erp",
    "type": "sqlserver",
    "success": true,
    "exit_code": 0,
    "duration_ms": 18600000
  },
  {
    "id": "sqlite_local",
    "type": "sqlite",
    "success": true,
    "exit_code": 0,
    "duration_ms": 400000
  }
]
```

#### Executing Single Database Check
```bash
./dbchecker -key-file /etc/dbchecker/master.key -config config.yaml -db mysql_orders
```

---

### Step 4: Programmatic Library API Reference

For detailed programmatic Go library integration patterns, code examples, and HTTP server integration guides (such as `health-checker`), please refer to the [Package Integration section in ARCHITECTURE.md](./ARCHITECTURE.md#package-integration).

---

## 7. Testing Documentation

For comprehensive details on test architecture, test execution instructions (PowerShell / Bash), coverage reports, and troubleshooting guides, please refer to [TESTING.md](./TESTING.md).
