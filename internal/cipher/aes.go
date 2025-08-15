package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
)

// AESCipher provides AES-GCM encryption and decryption
type AESCipher struct {
	aead cipher.AEAD
}

// NewAESCipher creates a new AES cipher with the given key
// The key must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256
func NewAESCipher(key []byte) (*AESCipher, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("invalid key size: got %d bytes, expected %d bytes", len(key), 32)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-GCM cipher: %w", err)
	}

	return &AESCipher{
		aead: aead,
	}, nil
}

// Encrypt encrypts the plaintext and returns the ciphertext with nonce prepended
func (c *AESCipher) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("encryption failed: plaintext is empty")
	}

	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("encryption failed: unable to generate nonce: %w", err)
	}

	ciphertext := c.aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts the ciphertext (which should have nonce prepended) and returns the plaintext
func (c *AESCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("decryption failed: ciphertext is empty")
	}

	nonceSize := c.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("decryption failed: ciphertext too short, got %d bytes but need at least %d bytes for nonce", len(ciphertext), nonceSize)
	}

	nonce := ciphertext[:nonceSize]
	ciphertext = ciphertext[nonceSize:]

	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("decryption failed: %w", err)
	}

	return plaintext, nil
}
