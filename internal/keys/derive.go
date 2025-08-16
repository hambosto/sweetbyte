package keys

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/config"
	"golang.org/x/crypto/argon2"
)

// Argon2id Parameters
const (
	ArgonTime    uint32 = 4          // Time cost
	ArgonMemory  uint32 = 128 * 1024 // Memory cost (128MB)
	ArgonThreads uint8  = 4          // Parallelism
)

// Hash returns the Argon2id hash for the given password and salt
func Hash(password, salt []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}

	if len(salt) != config.SaltSize {
		return nil, fmt.Errorf("expected %d bytes, got %d", config.SaltSize, len(salt))
	}

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

// GetRandomSalt returns a new random salt
func GetRandomSalt(size int) ([]byte, error) {
	salt := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate nonce: %w", err)
	}
	return salt, nil
}
