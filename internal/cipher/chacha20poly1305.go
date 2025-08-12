package cipher

import (
	"crypto/cipher"
	"crypto/rand"
	"io"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/errors"
	"golang.org/x/crypto/chacha20poly1305"
)

// XChaCha20Cipher provides ChaCha20-Poly1305 encryption and decryption
type XChaCha20Cipher struct {
	aead cipher.AEAD
}

// NewXChaCha20Cipher creates a new XChaCha20-Poly1305 cipher with the given key
// XChaCha20 uses a 192-bit nonce instead of ChaCha20's 96-bit nonce
// The key must be exactly 32 bytes for XChaCha20
func NewXChaCha20Cipher(key []byte) (*XChaCha20Cipher, error) {
	if len(key) != config.KeySize/2 {
		return nil, errors.ErrInvalidKeySize
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	return &XChaCha20Cipher{
		aead: aead,
	}, nil
}

// Encrypt encrypts the plaintext and returns the ciphertext with nonce prepended
func (c *XChaCha20Cipher) Encrypt(plaintext []byte) ([]byte, error) {
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
func (c *XChaCha20Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
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
