// Package kdf provides key derivation functionalities.
package kdf

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/config"
	"golang.org/x/crypto/argon2"
)

const (
	// ArgonTime is the number of iterations for Argon2id.
	ArgonTime = 8
	// ArgonMemory is the memory usage in KiB for Argon2id.
	ArgonMemory = 1 << 20
	// ArgonThreads is the number of threads for Argon2id.
	ArgonThreads = 8
)

// Hash derives a key from a password and salt using Argon2id.
func Hash(password, salt []byte) ([]byte, error) {
	// Ensure the password is not empty.
	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}

	// Ensure the salt has the correct size.
	if len(salt) != config.SaltSize {
		return nil, fmt.Errorf("expected %d bytes, got %d", config.SaltSize, len(salt))
	}

	// Derive the key using Argon2id.
	key := argon2.IDKey(
		password,
		salt,
		ArgonTime,
		ArgonMemory,
		ArgonThreads,
		config.MasterKeySize,
	)

	return key, nil
}

// GetRandomSalt generates a random salt of the given size.
func GetRandomSalt(size int) ([]byte, error) {
	salt := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}
