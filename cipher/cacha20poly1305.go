package cipher

import (
	"crypto/cipher"
	"fmt"

	"github.com/hambosto/sweetbyte/derive"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	NonceSizeX = 24
)

type ChaCha20Cipher struct {
	aead cipher.AEAD
}

func NewChaCha20Cipher(key []byte) (*ChaCha20Cipher, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("key must be %d bytes, got %d", KeySize, len(key))
	}

	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create XChaCha20-Poly1305 cipher: %w", err)
	}

	return &ChaCha20Cipher{aead: aead}, nil
}

func (c *ChaCha20Cipher) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("plaintext cannot be empty")
	}

	nonce, err := derive.GetRandomBytes(NonceSizeX)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := c.aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func (c *ChaCha20Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext cannot be empty")
	}

	if len(ciphertext) < NonceSizeX {
		return nil, fmt.Errorf("ciphertext too short, need at least %d bytes, got %d", NonceSizeX, len(ciphertext))
	}

	nonce := ciphertext[:NonceSizeX]
	ciphertext = ciphertext[NonceSizeX:]

	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	return plaintext, nil
}
