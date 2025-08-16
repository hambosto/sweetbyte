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
// It encapsulates the AEAD cipher and handles nonce generation and prepending.
type XChaCha20Cipher struct {
	aead cipher.AEAD
}

// NewXChaCha20Cipher creates a new XChaCha20Cipher instance.
// It initializes an XChaCha20-Poly1305 cipher with the provided 32-byte key.
func NewXChaCha20Cipher(key []byte) (*XChaCha20Cipher, error) {
	if len(key) != config.EncryptionKeySize {
		return nil, fmt.Errorf("key must be %d bytes, got %d", config.EncryptionKeySize, len(key))
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create XChaCha20-Poly1305 cipher: %w", err)
	}

	return &XChaCha20Cipher{
		aead: aead,
	}, nil
}

// Encrypt encrypts the given plaintext.
// It generates a random nonce, performs XChaCha20-Poly1305 encryption,
// and prepends the nonce to the resulting ciphertext.
func (c *XChaCha20Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("plaintext cannot be empty")
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := c.aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts the given ciphertext.
// It assumes the nonce is prepended to the ciphertext, extracts it,
// and then performs XChaCha20-Poly1305 decryption and authentication.
func (c *XChaCha20Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
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
