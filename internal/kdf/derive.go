// Package kdf provides key derivation functionality.
package kdf

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/config"
	"golang.org/x/crypto/argon2"
)

const (
	// ArgonTime is the number of iterations for Argon2.
	ArgonTime uint32 = 8
	// ArgonMemory is the memory usage in KiB for Argon2.
	ArgonMemory uint32 = 128 * 1024
	// ArgonThreads is the number of threads for Argon2.
	ArgonThreads uint8 = 8
)

// Hash derives a key from a password and salt using Argon2.
func Hash(password, salt []byte) ([]byte, error) {
	// Password cannot be empty.
	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}

	// Salt must be the correct size.
	if len(salt) != config.SaltSize {
		return nil, fmt.Errorf("expected %d bytes, got %d", config.SaltSize, len(salt))
	}

	// Derive the key using Argon2.
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

// GetRandomSalt generates a random salt of the specified size.
func GetRandomSalt(size int) ([]byte, error) {
	salt := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}
