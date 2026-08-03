/*
Package crypto provides AES-GCM encryption and decryption utilities for sensitive data like passwords,
leveraging libsecsecrets from secretprotector for key resolution, AES-256-GCM encryption/decryption, and memory hygiene.
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

// Encrypt encrypts a plaintext password using libsecsecrets AES-256-GCM and returns a Base64-encoded string.
func Encrypt(ctx context.Context, plaintext string, secretKey []byte) (string, error) {
	return libsecsecrets.Encrypt(ctx, plaintext, secretKey)
}

// Decrypt decrypts a Base64-encoded encrypted password using libsecsecrets AES-256-GCM and returns the plaintext.
func Decrypt(ctx context.Context, encryptedPassword string, secretKey []byte) (string, error) {
	return libsecsecrets.Decrypt(ctx, encryptedPassword, secretKey)
}

// ZeroBuffer zeroes sensitive byte slices in memory to minimize exposure.
func ZeroBuffer(b []byte) {
	libsecsecrets.ZeroBuffer(b)
}
