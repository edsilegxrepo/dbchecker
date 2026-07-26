package crypto_test

import (
	"context"
	"criticalsys/secretprotector/pkg/libsecsecrets"
	"testing"

	"criticalsys.net/dbchecker/crypto"
)

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

	// 4. Decrypt password
	decrypted, err := crypto.Decrypt(ctx, ciphertext, keyBytes)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	if decrypted != plaintext {
		t.Errorf("Expected decrypted text %q, got %q", plaintext, decrypted)
	}
}
