package cipher

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	KeySize    = 32
	NonceSize  = 12
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

type AESCipher struct {
	aead cipher.AEAD
}

func NewAESCipher(key []byte) (*AESCipher, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("key must be %d bytes, got %d", KeySize, len(key))
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
