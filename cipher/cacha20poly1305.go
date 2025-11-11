package cipher

import (
	"fmt"

	"sweetbyte/derive"
)

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
