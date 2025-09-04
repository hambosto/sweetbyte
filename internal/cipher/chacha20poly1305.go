// Package cipher provides cryptographic cipher implementations.
package cipher

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/config"
	"golang.org/x/crypto/chacha20poly1305"
)

// XChaCha20Cipher provides XChaCha20-Poly1305 encryption and decryption.
type XChaCha20Cipher struct {
	aead cipher.AEAD
}

// NewXChaCha20Cipher creates a new XChaCha20Cipher with the given key.
func NewXChaCha20Cipher(key []byte) (*XChaCha20Cipher, error) {
	// The key must be the correct size for XChaCha20-Poly1305.
	if len(key) != config.EncryptionKeySize {
		return nil, fmt.Errorf("key must be %d bytes, got %d", config.EncryptionKeySize, len(key))
	}

	// Create a new XChaCha20-Poly1305 AEAD.
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create XChaCha20-Poly1305 cipher: %w", err)
	}

	return &XChaCha20Cipher{aead: aead}, nil
}

// Encrypt encrypts the given plaintext.
func (c *XChaCha20Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	// Plaintext cannot be empty.
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("plaintext cannot be empty")
	}

	// Generate a random nonce.
	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the plaintext and prepend the nonce.
	// #nosec G407
	ciphertext := c.aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts the given ciphertext.
func (c *XChaCha20Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
	// Ciphertext cannot be empty.
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext cannot be empty")
	}

	// The ciphertext must be at least the size of the nonce.
	nonceSize := chacha20poly1305.NonceSizeX
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short, need at least %d bytes, got %d", nonceSize, len(ciphertext))
	}

	// Extract the nonce and the actual ciphertext.
	nonce := ciphertext[:nonceSize]
	ciphertext = ciphertext[nonceSize:]

	// Decrypt the ciphertext.
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	return plaintext, nil
}
