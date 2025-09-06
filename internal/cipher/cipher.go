// Package cipher provides cryptographic cipher implementations.
package cipher

// Cipher defines the interface for cryptographic ciphers.
type Cipher interface {
	Encrypt(plaintext []byte) ([]byte, error)
	Decrypt(ciphertext []byte) ([]byte, error)
}
