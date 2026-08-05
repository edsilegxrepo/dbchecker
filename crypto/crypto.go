/*
Package crypto provides AES-GCM encryption and decryption utilities for sensitive data like passwords,
leveraging libsecsecrets from secretprotector for key resolution, AES-256-GCM encryption/decryption, and memory hygiene.

Core Components:
  - ResolveKey: Multi-source key resolution (raw/env/file) with validation
  - Encrypt/Decrypt: String-based AES-256-GCM operations for config storage
  - DecryptBytes: Byte-based decryption enabling memory zeroing after use
  - ZeroBuffer: Secure memory clearing to minimize credential exposure

Data Flow:
 1. Master key resolved via ResolveKey (env var DB_SECRET_KEY or file)
 2. Passwords encrypted at rest in YAML config (v1:gcm: prefixed Base64-encoded ciphertext)
 3. DecryptBytes used at runtime to get zeroable []byte for database auth
 4. ZeroBuffer called after password used to clear from memory
*/
package crypto

import (
	"context"

	"github.com/edsilegxrepo/secretprotector/pkg/libsecsecrets"
)

// DefaultKeyEnv is the default environment variable name used for secret key resolution.
const DefaultKeyEnv = "DB_SECRET_KEY"

// ResolveKey resolves and validates the secret key from raw string, environment variable, or file path.
func ResolveKey(ctx context.Context, rawKey, envVar, keyFile string) ([]byte, error) {
	if envVar == "" {
		envVar = DefaultKeyEnv
	}
	return libsecsecrets.ResolveKey(ctx, rawKey, envVar, keyFile)
}

// IsEncrypted checks if a string has the v1:gcm: encrypted prefix.
func IsEncrypted(s string) bool {
	return libsecsecrets.IsEncrypted(s)
}

// Encrypt encrypts a plaintext password using libsecsecrets AES-256-GCM.
// Returns the encrypted value with v1:gcm: prefix for identification.
func Encrypt(ctx context.Context, plaintext string, secretKey []byte) (string, error) {
	return libsecsecrets.Encrypt(ctx, plaintext, secretKey)
}

// Decrypt decrypts an encrypted password and returns the plaintext.
// Accepts values with or without the v1:gcm: prefix for backwards compatibility.
func Decrypt(ctx context.Context, encryptedPassword string, secretKey []byte) (string, error) {
	return libsecsecrets.Decrypt(ctx, encryptedPassword, secretKey)
}

// DecryptBytes decrypts an encrypted password and returns the plaintext as []byte.
// Unlike Decrypt() which returns an immutable string, the returned []byte can be zeroed after use.
// Callers SHOULD defer ZeroBuffer() on the result to clear sensitive data from memory.
// This is the preferred decryption method for database password handling.
// Accepts values with or without the v1:gcm: prefix for backwards compatibility.
func DecryptBytes(ctx context.Context, encryptedPassword string, secretKey []byte) ([]byte, error) {
	return libsecsecrets.DecryptBytes(ctx, []byte(encryptedPassword), secretKey)
}

// ZeroBuffer zeroes sensitive byte slices in memory to minimize exposure.
func ZeroBuffer(b []byte) {
	libsecsecrets.ZeroBuffer(b)
}
