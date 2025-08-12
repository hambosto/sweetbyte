package cipher

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/hambosto/sweetbyte/internal/cipher"
	"github.com/hambosto/sweetbyte/internal/config"
)

// CipherInterface defines the common interface for both cipher implementations
type CipherInterface interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}

// TestBothCiphers_Compatibility tests that both ciphers work with the same interface
func TestBothCiphers_Compatibility(t *testing.T) {
	key := make([]byte, config.KeySize)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}

	// Create both cipher instances
	aesCipher, err := cipher.NewAESCipher(key)
	if err != nil {
		t.Fatalf("failed to create AES cipher: %v", err)
	}

	chachaCipher, err := cipher.NewXChaCha20Cipher(key)
	if err != nil {
		t.Fatalf("failed to create XChaCha20 cipher: %v", err)
	}

	ciphers := []struct {
		name   string
		cipher CipherInterface
	}{
		{"AES-GCM", aesCipher},
		{"XChaCha20-Poly1305", chachaCipher},
	}

	plaintext := []byte("Hello, World! This is a test message.")

	for _, c := range ciphers {
		t.Run(c.name, func(t *testing.T) {
			// Test encryption
			ciphertext, err := c.cipher.Encrypt(plaintext)
			if err != nil {
				t.Fatalf("Encrypt() error = %v", err)
			}

			if len(ciphertext) <= len(plaintext) {
				t.Error("ciphertext should be longer than plaintext")
			}

			// Test decryption
			decrypted, err := c.cipher.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}

			if !bytes.Equal(plaintext, decrypted) {
				t.Errorf("decrypted text doesn't match original: got %v, want %v", decrypted, plaintext)
			}
		})
	}
}

// TestBothCiphers_IncompatibleCiphertexts tests that ciphertexts from one cipher cannot be decrypted by another
func TestBothCiphers_IncompatibleCiphertexts(t *testing.T) {
	key := make([]byte, config.KeySize)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}

	aesCipher, err := cipher.NewAESCipher(key)
	if err != nil {
		t.Fatalf("failed to create AES cipher: %v", err)
	}

	chachaCipher, err := cipher.NewXChaCha20Cipher(key)
	if err != nil {
		t.Fatalf("failed to create XChaCha20 cipher: %v", err)
	}

	plaintext := []byte("Hello, World!")

	// Encrypt with AES
	aesCiphertext, err := aesCipher.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("AES Encrypt() error = %v", err)
	}

	// Encrypt with XChaCha20
	chachaCiphertext, err := chachaCipher.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("XChaCha20 Encrypt() error = %v", err)
	}

	// Try to decrypt AES ciphertext with XChaCha20 (should fail)
	_, err = chachaCipher.Decrypt(aesCiphertext)
	if err == nil {
		t.Error("XChaCha20 should not be able to decrypt AES ciphertext")
	}

	// Try to decrypt XChaCha20 ciphertext with AES (should fail)
	_, err = aesCipher.Decrypt(chachaCiphertext)
	if err == nil {
		t.Error("AES should not be able to decrypt XChaCha20 ciphertext")
	}
}

// TestBothCiphers_DifferentNonceSizes tests that the ciphers use different nonce sizes
func TestBothCiphers_DifferentNonceSizes(t *testing.T) {
	key := make([]byte, config.KeySize)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}

	aesCipher, err := cipher.NewAESCipher(key)
	if err != nil {
		t.Fatalf("failed to create AES cipher: %v", err)
	}

	chachaCipher, err := cipher.NewXChaCha20Cipher(key)
	if err != nil {
		t.Fatalf("failed to create XChaCha20 cipher: %v", err)
	}

	plaintext := []byte("Hello, World!")

	aesCiphertext, err := aesCipher.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("AES Encrypt() error = %v", err)
	}

	chachaCiphertext, err := chachaCipher.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("XChaCha20 Encrypt() error = %v", err)
	}

	// AES-GCM uses 12-byte nonce, XChaCha20 uses 24-byte nonce
	aesNonceSize := 12
	chachaNonceSize := 24

	// Check that the ciphertexts have different structures due to nonce sizes
	if len(aesCiphertext) < aesNonceSize {
		t.Errorf("AES ciphertext too short to contain nonce")
	}

	if len(chachaCiphertext) < chachaNonceSize {
		t.Errorf("XChaCha20 ciphertext too short to contain nonce")
	}

	// The difference in ciphertext length should be the difference in nonce sizes (assuming same plaintext and tag size)
	expectedLengthDifference := chachaNonceSize - aesNonceSize
	actualLengthDifference := len(chachaCiphertext) - len(aesCiphertext)

	if actualLengthDifference != expectedLengthDifference {
		t.Errorf("ciphertext length difference = %d, want %d", actualLengthDifference, expectedLengthDifference)
	}
}

// BenchmarkComparison_Encrypt compares encryption performance of both ciphers
func BenchmarkComparison_Encrypt(b *testing.B) {
	key := make([]byte, config.KeySize)
	_, err := rand.Read(key)
	if err != nil {
		b.Fatalf("failed to generate random key: %v", err)
	}

	aesCipher, err := cipher.NewAESCipher(key)
	if err != nil {
		b.Fatalf("failed to create AES cipher: %v", err)
	}

	chachaCipher, err := cipher.NewXChaCha20Cipher(key)
	if err != nil {
		b.Fatalf("failed to create XChaCha20 cipher: %v", err)
	}

	plaintext := bytes.Repeat([]byte("A"), 1024) // 1KB

	b.Run("AES-GCM", func(b *testing.B) {
		b.ResetTimer()
		for b.Loop() {
			_, err := aesCipher.Encrypt(plaintext)
			if err != nil {
				b.Fatalf("AES Encrypt() error = %v", err)
			}
		}
	})

	b.Run("XChaCha20-Poly1305", func(b *testing.B) {
		b.ResetTimer()
		for b.Loop() {
			_, err := chachaCipher.Encrypt(plaintext)
			if err != nil {
				b.Fatalf("XChaCha20 Encrypt() error = %v", err)
			}
		}
	})
}

// BenchmarkComparison_Decrypt compares decryption performance of both ciphers
func BenchmarkComparison_Decrypt(b *testing.B) {
	key := make([]byte, config.KeySize)
	_, err := rand.Read(key)
	if err != nil {
		b.Fatalf("failed to generate random key: %v", err)
	}

	aesCipher, err := cipher.NewAESCipher(key)
	if err != nil {
		b.Fatalf("failed to create AES cipher: %v", err)
	}

	chachaCipher, err := cipher.NewXChaCha20Cipher(key)
	if err != nil {
		b.Fatalf("failed to create XChaCha20 cipher: %v", err)
	}

	plaintext := bytes.Repeat([]byte("A"), 1024) // 1KB

	aesCiphertext, err := aesCipher.Encrypt(plaintext)
	if err != nil {
		b.Fatalf("failed to encrypt with AES: %v", err)
	}

	chachaCiphertext, err := chachaCipher.Encrypt(plaintext)
	if err != nil {
		b.Fatalf("failed to encrypt with XChaCha20: %v", err)
	}

	b.Run("AES-GCM", func(b *testing.B) {
		b.ResetTimer()
		for b.Loop() {
			_, err := aesCipher.Decrypt(aesCiphertext)
			if err != nil {
				b.Fatalf("AES Decrypt() error = %v", err)
			}
		}
	})

	b.Run("XChaCha20-Poly1305", func(b *testing.B) {
		b.ResetTimer()
		for b.Loop() {
			_, err := chachaCipher.Decrypt(chachaCiphertext)
			if err != nil {
				b.Fatalf("XChaCha20 Decrypt() error = %v", err)
			}
		}
	})
}

// TestBothCiphers_LargeData tests both ciphers with large data
func TestBothCiphers_LargeData(t *testing.T) {
	key := make([]byte, config.KeySize)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}

	aesCipher, err := cipher.NewAESCipher(key)
	if err != nil {
		t.Fatalf("failed to create AES cipher: %v", err)
	}

	chachaCipher, err := cipher.NewXChaCha20Cipher(key)
	if err != nil {
		t.Fatalf("failed to create XChaCha20 cipher: %v", err)
	}

	// Test with 1MB of data
	largeData := make([]byte, 1024*1024)
	_, err = rand.Read(largeData)
	if err != nil {
		t.Fatalf("failed to generate large data: %v", err)
	}

	ciphers := []struct {
		name   string
		cipher CipherInterface
	}{
		{"AES-GCM", aesCipher},
		{"XChaCha20-Poly1305", chachaCipher},
	}

	for _, c := range ciphers {
		t.Run(c.name+"_1MB", func(t *testing.T) {
			// Encrypt
			ciphertext, err := c.cipher.Encrypt(largeData)
			if err != nil {
				t.Fatalf("Encrypt() error = %v", err)
			}

			// Decrypt
			decrypted, err := c.cipher.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}

			// Verify
			if !bytes.Equal(largeData, decrypted) {
				t.Error("large data roundtrip failed")
			}
		})
	}
}
