// Package cipher provides implementations of cryptographic ciphers used for encryption and decryption.
// It includes AES-256-GCM and XChaCha20-Poly1305, offering robust and secure data protection.
package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/config"
)

// AESCipher provides AES-256-GCM symmetric encryption and decryption capabilities.
// It encapsulates the authenticated encryption with associated data (AEAD) interface
// for secure cryptographic operations.
type AESCipher struct {
	aead cipher.AEAD // The authenticated encryption with associated data cipher.
}

// NewAESCipher creates and returns a new AESCipher instance.
// It initializes an AES block cipher with the provided key and wraps it with GCM (Galois/Counter Mode).
// The key must be 32 bytes long for AES-256.
func NewAESCipher(key []byte) (*AESCipher, error) {
	if len(key) != config.EncryptionKeySize { // Validate the key length for AES-256.
		return nil, fmt.Errorf("key must be %d bytes, got %d", config.EncryptionKeySize, len(key)) // Return error for invalid key size.
	}

	block, err := aes.NewCipher(key) // Create a new AES cipher block from the key.
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err) // Propagate error if block cipher creation fails.
	}

	aead, err := cipher.NewGCM(block) // Wrap the AES block cipher with GCM for authenticated encryption.
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-GCM cipher: %w", err) // Propagate error if GCM creation fails.
	}

	return &AESCipher{
		aead: aead, // Assign the initialized AEAD cipher.
	}, nil
}

// Encrypt encrypts the given plaintext using AES-256-GCM.
// It generates a random nonce, encrypts the data, and prepends the nonce to the ciphertext.
// The resulting ciphertext includes the GCM authentication tag.
func (c *AESCipher) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 { // Check if the plaintext is empty.
		return nil, fmt.Errorf("plaintext cannot be empty") // Return error for empty plaintext.
	}

	nonce := make([]byte, c.aead.NonceSize())                  // Create a byte slice for the nonce with the correct size.
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil { // Fill the nonce with cryptographically secure random bytes.
		return nil, fmt.Errorf("failed to generate nonce: %w", err) // Propagate error if nonce generation fails.
	}

	// Seal encrypts and authenticates the plaintext.
	// The nonce is prepended to the ciphertext for convenient storage and retrieval.
	ciphertext := c.aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil // Return the combined nonce and ciphertext.
}

// Decrypt decrypts the given ciphertext using AES-256-GCM.
// It extracts the nonce from the beginning of the ciphertext, then attempts to decrypt and authenticate the data.
// Returns an error if the authentication fails (indicating tampering or incorrect key).
func (c *AESCipher) Decrypt(ciphertext []byte) ([]byte, error) {
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
