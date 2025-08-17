// Package cipher provides implementations of cryptographic ciphers used for encryption and decryption.
// It includes AES-256-GCM and XChaCha20-Poly1305, offering robust and secure data protection.
package cipher

import (
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/config"
	"golang.org/x/crypto/chacha20poly1305"
)

// XChaCha20Cipher provides XChaCha20-Poly1305 symmetric encryption and decryption capabilities.
// It utilizes the extended nonce variant of ChaCha20, offering a larger nonce space for enhanced security.
type XChaCha20Cipher struct {
	aead cipher.AEAD // The authenticated encryption with associated data cipher.
}

// NewXChaCha20Cipher creates and returns a new XChaCha20Cipher instance.
// It initializes an XChaCha20-Poly1305 cipher with the provided key.
// The key must be 32 bytes long for XChaCha20.
func NewXChaCha20Cipher(key []byte) (*XChaCha20Cipher, error) {
	if len(key) != config.EncryptionKeySize { // Validate the key length for XChaCha20.
		return nil, fmt.Errorf("key must be %d bytes, got %d", config.EncryptionKeySize, len(key)) // Return error for invalid key size.
	}

	aead, err := chacha20poly1305.NewX(key) // Create a new XChaCha20-Poly1305 cipher with the given key.
	if err != nil {
		return nil, fmt.Errorf("failed to create XChaCha20-Poly1305 cipher: %w", err) // Propagate error if cipher creation fails.
	}

	return &XChaCha20Cipher{
		aead: aead, // Assign the initialized AEAD cipher.
	}, nil
}

// Encrypt encrypts the given plaintext using XChaCha20-Poly1305.
// It generates a random extended nonce, encrypts the data, and prepends the nonce to the ciphertext.
// The resulting ciphertext includes the Poly1305 authentication tag.
func (c *XChaCha20Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 { // Check if the plaintext is empty.
		return nil, fmt.Errorf("plaintext cannot be empty") // Return error for empty plaintext.
	}

	nonce := make([]byte, chacha20poly1305.NonceSizeX)         // Create a byte slice for the extended nonce.
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil { // Fill the nonce with cryptographically secure random bytes.
		return nil, fmt.Errorf("failed to generate nonce: %w", err) // Propagate error if nonce generation fails.
	}

	// Seal encrypts and authenticates the plaintext.
	// The nonce is prepended to the ciphertext for convenient storage and retrieval.
	ciphertext := c.aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil // Return the combined nonce and ciphertext.
}

// Decrypt decrypts the given ciphertext using XChaCha20-Poly1305.
// It extracts the extended nonce from the beginning of the ciphertext, then attempts to decrypt and authenticate the data.
// Returns an error if the authentication fails (indicating tampering or incorrect key).
func (c *XChaCha20Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 { // Check if the ciphertext is empty.
		return nil, fmt.Errorf("ciphertext cannot be empty") // Return error for empty ciphertext.
	}

	nonceSize := c.aead.NonceSize()  // Get the expected nonce size.
	if len(ciphertext) < nonceSize { // Check if the ciphertext is too short to contain the nonce.
		return nil, fmt.Errorf("ciphertext too short, need at least %d bytes, got %d", nonceSize, len(ciphertext)) // Return error for short ciphertext.
	}

	nonce := ciphertext[:nonceSize]     // Extract the nonce from the beginning of the ciphertext.
	ciphertext = ciphertext[nonceSize:] // Get the actual ciphertext (excluding the nonce).

	// Open decrypts and authenticates the ciphertext.
	// If authentication fails, an error is returned.
	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err) // Return error if decryption or authentication fails.
	}

	return plaintext, nil // Return the decrypted plaintext.
}
