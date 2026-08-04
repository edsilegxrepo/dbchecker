# Design - DB Connection Diags

## Design Principles

### 1. Extensibility
The application is designed to support new database types with minimal changes to the core logic. 
- To add a new database:
    1. Implement the `DB` interface in a new file within the `database/` package.
    2. Register the driver via `database.RegisterDriver("typename", factory)` in an `init()` function.
    3. The self-registering plugin pattern means no changes to `New()` or central config are needed.

### 2. Security by Default
- **AES-GCM**: Chosen for its performance and built-in integrity checking.
- **Lazy Connection (MongoDB v2)**: The MongoDB implementation follows the v2 driver design where `Connect` initializes the client, but actual connection health is verified via `Ping`.
- **Scoped IO**: All file operations (Config, TLS certificates) are scoped to their respective parent directories using Go 1.24 `os.Root` to mitigate CWE-22 (Path Traversal).

### 3. Concurrency
- When checking multiple databases, the application uses a `sync.WaitGroup` with a bounded semaphore channel to run checks in parallel with configurable concurrency limits (`WithConcurrency` option). Results are returned in deterministic alphabetical order by database ID for reproducibility.

### 4. Error Handling
- Errors are wrapped with context (e.g., `fmt.Errorf("connection failed for %s: %w", ...)`) to ensure that logs provide clear information about which database failed and why, while preserving the underlying error for programmatic inspection if needed.

## Data Flow
1. **Input**: User provides `-config`, `-db` (optional), and a secret key (via `-key-file` or `DB_SECRET_KEY` env).
2. **Process**:
    - Resolve master secret key via `crypto.ResolveKey()`.
    - Load and validate YAML configuration.
    - For each target database (sorted alphabetically for deterministic output):
        - Decrypt password using `crypto.DecryptBytes()` (returns `[]byte` for memory hygiene).
        - Instantiate driver via `database.New()` factory.
        - Call `Connect()` with timeout context.
        - Call `Ping()` to verify basic connectivity.
        - Call `HealthCheck()` (if query provided) to verify functional status.
        - Zero the decrypted password buffer via `crypto.ZeroBuffer()`.
3. **Output**: Success message or detailed error per database, with granular exit codes (0-5) and step identification.
