package cipher

import (
	"fmt"

	"github.com/hambosto/sweetbyte/cipher/algorithm"
	"github.com/hambosto/sweetbyte/derive"
)

type Cipher struct {
	aesCipher    *algorithm.AESCipher
	chachaCipher *algorithm.ChaCha20Cipher
}

func NewCipher(key []byte) (*Cipher, error) {
	if len(key) < derive.ArgonKeyLen {
		return nil, fmt.Errorf("key must be at least 64 bytes for unified cipher")
	}

	aesCipher, err := algorithm.NewAESCipher(key[:32])
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher: %w", err)
	}

	chachaCipher, err := algorithm.NewChaCha20Cipher(key[32:64])
	if err != nil {
		return nil, fmt.Errorf("failed to create ChaCha20 cipher: %w", err)
	}

	return &Cipher{
		aesCipher:    aesCipher,
		chachaCipher: chachaCipher,
	}, nil
}

func (c *Cipher) EncryptAES(plaintext []byte) ([]byte, error) {
	return c.aesCipher.Encrypt(plaintext)
}

func (c *Cipher) DecryptAES(ciphertext []byte) ([]byte, error) {
	return c.aesCipher.Decrypt(ciphertext)
}

func (c *Cipher) EncryptChaCha20(plaintext []byte) ([]byte, error) {
	return c.chachaCipher.Encrypt(plaintext)
}

func (c *Cipher) DecryptChaCha20(ciphertext []byte) ([]byte, error) {
	return c.chachaCipher.Decrypt(ciphertext)
}
