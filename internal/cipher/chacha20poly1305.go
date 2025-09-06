// Package cipher provides cryptographic operations for encryption and decryption.
package cipher

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/config"
	"golang.org/x/crypto/chacha20poly1305"
)

// ChaCha20Cipher defines the interface for ChaCha20-Poly1305 encryption and decryption.
type ChaCha20Cipher interface {
	// Encrypt encrypts plaintext using XChaCha20-Poly1305.
	Encrypt(plaintext []byte) ([]byte, error)
	// Decrypt decrypts ciphertext using XChaCha20-Poly1305.
	Decrypt(ciphertext []byte) ([]byte, error)
}

// chaCha20Cipher implements the ChaCha20Cipher interface.
type chaCha20Cipher struct {
	aead cipher.AEAD
}

// NewChaCha20Cipher creates a new ChaCha20Cipher with the given key.
// It initializes an XChaCha20-Poly1305 AEAD cipher.
func NewChaCha20Cipher(key []byte) (ChaCha20Cipher, error) {
	// Ensure the key has the required size.
	if len(key) != config.EncryptionKeySize {
		return nil, fmt.Errorf("key must be %d bytes, got %d", config.EncryptionKeySize, len(key))
	}

	// Create a new XChaCha20-Poly1305 AEAD cipher.
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create XChaCha20-Poly1305 cipher: %w", err)
	}

	return &chaCha20Cipher{aead: aead}, nil
}

// Encrypt encrypts the given plaintext.
// It generates a random nonce and seals the plaintext to produce the ciphertext.
func (c *chaCha20Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	// Ensure plaintext is not empty.
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("plaintext cannot be empty")
	}

	// Generate a random nonce. The nonce is stored at the beginning of the ciphertext.
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
// It extracts the nonce from the ciphertext and then opens it to get the plaintext.
func (c *chaCha20Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
	// Ensure ciphertext is not empty.
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext cannot be empty")
	}

	// Extract the nonce from the ciphertext.
	nonceSize := chacha20poly1305.NonceSizeX
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short, need at least %d bytes, got %d", nonceSize, len(ciphertext))
	}

	nonce := ciphertext[:nonceSize]
	ciphertext = ciphertext[nonceSize:]

	// Decrypt the ciphertext.
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	return plaintext, nil
}
