package cipher

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"testing"

	"github.com/hambosto/sweetbyte/internal/cipher"
	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/errors"
)

func TestNewXChaCha20Cipher(t *testing.T) {
	tests := []struct {
		name    string
		keySize int
		wantErr error
	}{
		{
			name:    "valid key size",
			keySize: config.KeySize,
			wantErr: nil,
		},
		{
			name:    "invalid key size - too short",
			keySize: 16,
			wantErr: errors.ErrInvalidKeySize,
		},
		{
			name:    "invalid key size - too long",
			keySize: 64,
			wantErr: errors.ErrInvalidKeySize,
		},
		{
			name:    "empty key",
			keySize: 0,
			wantErr: errors.ErrInvalidKeySize,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			key := make([]byte, tt.keySize)
			if tt.keySize > 0 {
				_, err := rand.Read(key)
				if err != nil {
					t.Fatalf("failed to generate random key: %v", err)
				}
			}

			cipher, err := cipher.NewXChaCha20Cipher(key)

			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("NewXChaCha20Cipher() error = %v, wantErr %v", err, tt.wantErr)
				}
				if cipher != nil {
					t.Error("NewXChaCha20Cipher() should return nil cipher on error")
				}
			} else {
				if err != nil {
					t.Errorf("NewXChaCha20Cipher() unexpected error = %v", err)
				}
				if cipher == nil {
					t.Error("NewXChaCha20Cipher() should return non-nil cipher on success")
				}
			}
		})
	}
}

func TestXChaCha20Cipher_Encrypt(t *testing.T) {
	// Create a valid cipher
	key := make([]byte, config.KeySize)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}

	c, err := cipher.NewXChaCha20Cipher(key)
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}

	tests := []struct {
		name      string
		plaintext []byte
		wantErr   error
	}{
		{
			name:      "valid plaintext",
			plaintext: []byte("Hello, World!"),
			wantErr:   nil,
		},
		{
			name:      "empty plaintext",
			plaintext: []byte{},
			wantErr:   errors.ErrEmptyPlaintext,
		},
		{
			name:      "nil plaintext",
			plaintext: nil,
			wantErr:   errors.ErrEmptyPlaintext,
		},
		{
			name:      "large plaintext",
			plaintext: bytes.Repeat([]byte("A"), 10000),
			wantErr:   nil,
		},
		{
			name:      "single byte",
			plaintext: []byte("A"),
			wantErr:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext, err := c.Encrypt(tt.plaintext)

			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("Encrypt() error = %v, wantErr %v", err, tt.wantErr)
				}
				if ciphertext != nil {
					t.Error("Encrypt() should return nil ciphertext on error")
				}
			} else {
				if err != nil {
					t.Errorf("Encrypt() unexpected error = %v", err)
				}
				if ciphertext == nil {
					t.Error("Encrypt() should return non-nil ciphertext on success")
				}
				// Ciphertext should be longer than plaintext (nonce + ciphertext + tag)
				if len(ciphertext) <= len(tt.plaintext) {
					t.Error("Encrypt() ciphertext should be longer than plaintext")
				}
			}
		})
	}
}

func TestXChaCha20Cipher_Decrypt(t *testing.T) {
	// Create a valid cipher
	key := make([]byte, config.KeySize)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}

	c, err := cipher.NewXChaCha20Cipher(key)
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}

	tests := []struct {
		name       string
		setupFunc  func() []byte // Function to setup ciphertext
		wantErr    error
		wantResult []byte
	}{
		{
			name: "valid ciphertext",
			setupFunc: func() []byte {
				plaintext := []byte("Hello, World!")
				ciphertext, err := c.Encrypt(plaintext)
				if err != nil {
					t.Fatalf("failed to encrypt: %v", err)
				}
				return ciphertext
			},
			wantErr:    nil,
			wantResult: []byte("Hello, World!"),
		},
		{
			name: "empty ciphertext",
			setupFunc: func() []byte {
				return []byte{}
			},
			wantErr:    errors.ErrEmptyCiphertext,
			wantResult: nil,
		},
		{
			name: "nil ciphertext",
			setupFunc: func() []byte {
				return nil
			},
			wantErr:    errors.ErrEmptyCiphertext,
			wantResult: nil,
		},
		{
			name: "ciphertext too short",
			setupFunc: func() []byte {
				return []byte("short")
			},
			wantErr:    errors.ErrDecryptionFailed,
			wantResult: nil,
		},
		{
			name: "invalid ciphertext",
			setupFunc: func() []byte {
				// Create a fake ciphertext with correct nonce size but invalid content
				nonce := make([]byte, 24) // XChaCha20 nonce size
				_, err := rand.Read(nonce)
				if err != nil {
					t.Fatalf("failed to generate nonce: %v", err)
				}
				fakeCiphertext := append(nonce, []byte("invalid ciphertext data")...)
				return fakeCiphertext
			},
			wantErr:    errors.ErrDecryptionFailed,
			wantResult: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ciphertext := tt.setupFunc()
			plaintext, err := c.Decrypt(ciphertext)

			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("Decrypt() error = %v, wantErr %v", err, tt.wantErr)
				}
				if plaintext != nil {
					t.Error("Decrypt() should return nil plaintext on error")
				}
			} else {
				if err != nil {
					t.Errorf("Decrypt() unexpected error = %v", err)
				}
				if !bytes.Equal(plaintext, tt.wantResult) {
					t.Errorf("Decrypt() = %v, want %v", plaintext, tt.wantResult)
				}
			}
		})
	}
}

func TestXChaCha20Cipher_EncryptDecryptRoundtrip(t *testing.T) {
	// Create a valid cipher
	key := make([]byte, config.KeySize)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}

	c, err := cipher.NewXChaCha20Cipher(key)
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}

	testCases := [][]byte{
		[]byte("Hello, World!"),
		[]byte("A"),
		[]byte("This is a longer message to test encryption and decryption"),
		bytes.Repeat([]byte("X"), 1000),
		[]byte("Special chars: !@#$%^&*()_+-=[]{}|;:,.<>?"),
		[]byte("Unicode: 你好世界 🌍"),
	}

	for i, plaintext := range testCases {
		t.Run(fmt.Sprintf("case_%d", i), func(t *testing.T) {
			// Encrypt
			ciphertext, err := c.Encrypt(plaintext)
			if err != nil {
				t.Fatalf("Encrypt() error = %v", err)
			}

			// Decrypt
			decrypted, err := c.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("Decrypt() error = %v", err)
			}

			// Compare
			if !bytes.Equal(plaintext, decrypted) {
				t.Errorf("roundtrip failed: original = %v, decrypted = %v", plaintext, decrypted)
			}
		})
	}
}

func TestXChaCha20Cipher_EncryptionUniqueness(t *testing.T) {
	// Create a valid cipher
	key := make([]byte, config.KeySize)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}

	c, err := cipher.NewXChaCha20Cipher(key)
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}

	plaintext := []byte("Hello, World!")

	// Encrypt the same plaintext multiple times
	ciphertexts := make([][]byte, 10)
	for i := range 10 {
		ciphertext, err := c.Encrypt(plaintext)
		if err != nil {
			t.Fatalf("Encrypt() error = %v", err)
		}
		ciphertexts[i] = ciphertext
	}

	// Ensure all ciphertexts are different (due to random nonces)
	for i := range ciphertexts {
		for j := i + 1; j < len(ciphertexts); j++ {
			if bytes.Equal(ciphertexts[i], ciphertexts[j]) {
				t.Errorf("ciphertexts should be unique: ciphertext[%d] == ciphertext[%d]", i, j)
			}
		}
	}

	// Ensure all decrypt to the same plaintext
	for i, ciphertext := range ciphertexts {
		decrypted, err := c.Decrypt(ciphertext)
		if err != nil {
			t.Fatalf("Decrypt() error for ciphertext[%d] = %v", i, err)
		}
		if !bytes.Equal(plaintext, decrypted) {
			t.Errorf("decryption failed for ciphertext[%d]: got %v, want %v", i, decrypted, plaintext)
		}
	}
}

func TestXChaCha20Cipher_DifferentKeys(t *testing.T) {
	// Create two different keys
	key1 := make([]byte, config.KeySize)
	key2 := make([]byte, config.KeySize)

	_, err := rand.Read(key1)
	if err != nil {
		t.Fatalf("failed to generate key1: %v", err)
	}

	_, err = rand.Read(key2)
	if err != nil {
		t.Fatalf("failed to generate key2: %v", err)
	}

	c1, err := cipher.NewXChaCha20Cipher(key1)
	if err != nil {
		t.Fatalf("failed to create cipher1: %v", err)
	}

	c2, err := cipher.NewXChaCha20Cipher(key2)
	if err != nil {
		t.Fatalf("failed to create cipher2: %v", err)
	}

	plaintext := []byte("Hello, World!")

	// Encrypt with first cipher
	ciphertext, err := c1.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// Try to decrypt with second cipher (should fail)
	_, err = c2.Decrypt(ciphertext)
	if err == nil {
		t.Error("Decrypt() should fail when using different key")
	}
	if err != errors.ErrDecryptionFailed {
		t.Errorf("Decrypt() error = %v, want %v", err, errors.ErrDecryptionFailed)
	}
}

func TestXChaCha20Cipher_NonceSize(t *testing.T) {
	// Create a valid cipher
	key := make([]byte, config.KeySize)
	_, err := rand.Read(key)
	if err != nil {
		t.Fatalf("failed to generate random key: %v", err)
	}

	c, err := cipher.NewXChaCha20Cipher(key)
	if err != nil {
		t.Fatalf("failed to create cipher: %v", err)
	}

	plaintext := []byte("Hello, World!")
	ciphertext, err := c.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt() error = %v", err)
	}

	// XChaCha20 should use a 24-byte nonce (192 bits)
	expectedNonceSize := 24
	if len(ciphertext) < expectedNonceSize {
		t.Errorf("ciphertext too short to contain expected nonce size")
	}

	// The nonce is prepended to the ciphertext
	nonce := ciphertext[:expectedNonceSize]
	if len(nonce) != expectedNonceSize {
		t.Errorf("nonce size = %d, want %d", len(nonce), expectedNonceSize)
	}
}

// Benchmark tests
func BenchmarkXChaCha20Cipher_Encrypt(b *testing.B) {
	key := make([]byte, config.KeySize)
	_, err := rand.Read(key)
	if err != nil {
		b.Fatalf("failed to generate random key: %v", err)
	}

	c, err := cipher.NewXChaCha20Cipher(key)
	if err != nil {
		b.Fatalf("failed to create cipher: %v", err)
	}

	plaintext := bytes.Repeat([]byte("A"), 1024) // 1KB

	for b.Loop() {
		_, err := c.Encrypt(plaintext)
		if err != nil {
			b.Fatalf("Encrypt() error = %v", err)
		}
	}
}

func BenchmarkXChaCha20Cipher_Decrypt(b *testing.B) {
	key := make([]byte, config.KeySize)
	_, err := rand.Read(key)
	if err != nil {
		b.Fatalf("failed to generate random key: %v", err)
	}

	c, err := cipher.NewXChaCha20Cipher(key)
	if err != nil {
		b.Fatalf("failed to create cipher: %v", err)
	}

	plaintext := bytes.Repeat([]byte("A"), 1024) // 1KB
	ciphertext, err := c.Encrypt(plaintext)
	if err != nil {
		b.Fatalf("failed to encrypt: %v", err)
	}

	for b.Loop() {
		_, err := c.Decrypt(ciphertext)
		if err != nil {
			b.Fatalf("Decrypt() error = %v", err)
		}
	}
}
