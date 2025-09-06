// Package cipher provides cryptographic operations for encryption and decryption.
package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/config"
)

// AESCipher defines the interface for AES encryption and decryption.
type AESCipher interface {
	// Encrypt encrypts plaintext using AES-GCM.
	Encrypt(plaintext []byte) ([]byte, error)
	// Decrypt decrypts ciphertext using AES-GCM.
	Decrypt(ciphertext []byte) ([]byte, error)
}

// aesCipher implements the AESCipher interface using AES-GCM.
type aesCipher struct {
	aead cipher.AEAD
}

// NewAESCipher creates a new AESCipher with the given key.
// It initializes an AES-GCM cipher with a key of a specific size.
func NewAESCipher(key []byte) (AESCipher, error) {
	// Ensure the key has the required size.
	if len(key) != config.EncryptionKeySize {
		return nil, fmt.Errorf("key must be %d bytes, got %d", config.EncryptionKeySize, len(key))
	}

	// Create a new AES cipher block.
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	// Create a new GCM AEAD cipher.
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-GCM cipher: %w", err)
	}

	return &aesCipher{aead: aead}, nil
}

// Encrypt encrypts the given plaintext.
// It generates a random nonce, and then seals the plaintext to produce the ciphertext.
func (c *aesCipher) Encrypt(plaintext []byte) ([]byte, error) {
	// Ensure plaintext is not empty.
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("plaintext cannot be empty")
	}

	// Generate a random nonce. The nonce is stored at the beginning of the ciphertext.
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	// Encrypt the plaintext and prepend the nonce.
	ciphertext := c.aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts the given ciphertext.
// It extracts the nonce from the beginning of the ciphertext and then opens it to get the plaintext.
func (c *aesCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	// Ensure ciphertext is not empty.
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext cannot be empty")
	}

	// Extract the nonce from the ciphertext.
	nonceSize := c.aead.NonceSize()
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
