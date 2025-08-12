package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/errors"
)

// AESCipher provides AES-GCM encryption and decryption
type AESCipher struct {
	aead cipher.AEAD
}

// NewAESCipher creates a new AES cipher with the given key
// The key must be 16, 24, or 32 bytes for AES-128, AES-192, or AES-256
func NewAESCipher(key []byte) (*AESCipher, error) {
	if len(key) != config.KeySize/2 {
		return nil, errors.ErrInvalidKeySize
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	return &AESCipher{
		aead: aead,
	}, nil
}

// Encrypt encrypts the plaintext and returns the ciphertext with nonce prepended
func (c *AESCipher) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, errors.ErrEmptyPlaintext
	}

	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := c.aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

// Decrypt decrypts the ciphertext (which should have nonce prepended) and returns the plaintext
func (c *AESCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, errors.ErrEmptyCiphertext
	}

	nonceSize := c.aead.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, errors.ErrDecryptionFailed
	}

	nonce := ciphertext[:nonceSize]
	ciphertext = ciphertext[nonceSize:]

	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errors.ErrDecryptionFailed
	}

	return plaintext, nil
}
