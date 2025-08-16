package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/config"
)

// AESCipher provides AES-256-GCM encryption and decryption capabilities.
// It encapsulates the AEAD cipher and handles nonce generation and prepending.
type AESCipher struct {
	aead cipher.AEAD
}

// NewAESCipher creates a new AESCipher instance.
// It initializes an AES-256-GCM cipher with the provided 32-byte key.
func NewAESCipher(key []byte) (*AESCipher, error) {
	if len(key) != config.EncryptionKeySize {
		return nil, fmt.Errorf("key must be %d bytes, got %d", config.EncryptionKeySize, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-GCM cipher: %w", err)
	}

	return &AESCipher{
		aead: aead,
	}, nil
}

// Encrypt encrypts the given plaintext.
// It generates a random nonce, performs AES-GCM encryption,
// and prepends the nonce to the resulting ciphertext.
func (c *AESCipher) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("plaintext cannot be empty")
	}

	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := c.aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts the given ciphertext.
// It assumes the nonce is prepended to the ciphertext, extracts it,
// and then performs AES-GCM decryption and authentication.
func (c *AESCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext cannot be empty")
	}

	nonceSize := c.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short, need at least %d bytes, got %d", nonceSize, len(ciphertext))
	}

	nonce := ciphertext[:nonceSize]
	ciphertext = ciphertext[nonceSize:]

	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	return plaintext, nil
}
