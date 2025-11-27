package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"github.com/hambosto/sweetbyte/derive"
)

const (
	AESKeySize   = 32
	AESNonceSize = 12
)

type AESCipher struct {
	aead cipher.AEAD
}

func NewAESCipher(key []byte) (*AESCipher, error) {
	if len(key) != AESKeySize {
		return nil, fmt.Errorf("key must be %d bytes, got %d", AESKeySize, len(key))
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create cipher: %w", err)
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-GCM cipher: %w", err)
	}

	return &AESCipher{aead: aead}, nil
}

func (c *AESCipher) Encrypt(plaintext []byte) ([]byte, error) {
	if len(plaintext) == 0 {
		return nil, fmt.Errorf("plaintext cannot be empty")
	}

	nonce, err := derive.GetRandomBytes(AESNonceSize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}

	ciphertext := c.aead.Seal(nonce, nonce, plaintext, nil)
	return ciphertext, nil
}

func (c *AESCipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) == 0 {
		return nil, fmt.Errorf("ciphertext cannot be empty")
	}

	if len(ciphertext) < AESNonceSize {
		return nil, fmt.Errorf("ciphertext too short, need at least %d bytes, got %d", AESNonceSize, len(ciphertext))
	}

	nonce := ciphertext[:AESNonceSize]
	ciphertext = ciphertext[AESNonceSize:]

	plaintext, err := c.aead.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, fmt.Errorf("authentication failed: %w", err)
	}

	return plaintext, nil
}
