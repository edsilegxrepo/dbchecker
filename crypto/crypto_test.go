/*
Integration tests for the crypto wrapper around secretprotector/libsecsecrets.

Test Strategy:
  - Verifies end-to-end: GenerateKey -> ResolveKey -> Encrypt -> Decrypt -> ZeroBuffer
  - Tests DecryptBytes returns []byte (zeroable) vs Decrypt returns string (not zeroable)
  - Validates ZeroBuffer clears sensitive data from memory

Security Verification:
  - Ciphertext is distinct from plaintext (AES-256-GCM)
  - Decryption recovers original plaintext
  - ZeroBuffer overwrites all bytes with 0x00
*/
package crypto_test

import (
	"context"
	"testing"

	"github.com/edsilegxrepo/secretprotector/pkg/libsecsecrets"

	"github.com/edsilegxrepo/dbchecker/crypto"
)

// TestCryptoIntegration verifies the full encrypt/decrypt lifecycle with memory hygiene.
func TestCryptoIntegration(t *testing.T) {
	ctx := context.Background()

	// 1. Generate a valid 64-char hex key using secretprotector
	rawKey, err := libsecsecrets.GenerateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	// 2. Resolve key using crypto wrapper
	keyBytes, err := crypto.ResolveKey(ctx, rawKey, "", "")
	if err != nil {
		t.Fatalf("Failed to resolve key: %v", err)
	}
	defer crypto.ZeroBuffer(keyBytes)

	if len(keyBytes) != 32 {
		t.Errorf("Expected 32-byte key, got %d bytes", len(keyBytes))
	}

	// 3. Encrypt password
	plaintext := "SecretP@ssw0rd!2026"
	ciphertext, err := crypto.Encrypt(ctx, plaintext, keyBytes)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	if ciphertext == "" || ciphertext == plaintext {
		t.Errorf("Ciphertext should be a non-empty base64 string distinct from plaintext")
	}

	// 4. Decrypt password (string version)
	decrypted, err := crypto.Decrypt(ctx, ciphertext, keyBytes)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Expected decrypted text %q, got %q", plaintext, decrypted)
	}

	// 5. DecryptBytes returns []byte that can be zeroed
	decryptedBytes, err := crypto.DecryptBytes(ctx, ciphertext, keyBytes)
	if err != nil {
		t.Fatalf("DecryptBytes failed: %v", err)
	}

	if string(decryptedBytes) != plaintext {
		t.Errorf("Expected DecryptBytes result %q, got %q", plaintext, string(decryptedBytes))
	}

	// Verify ZeroBuffer clears the data
	crypto.ZeroBuffer(decryptedBytes)
	for i, b := range decryptedBytes {
		if b != 0 {
			t.Errorf("ZeroBuffer failed to clear byte at index %d: got %d", i, b)
		}
	}
}
