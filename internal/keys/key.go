package keys

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/errors"
	"golang.org/x/crypto/argon2"
)

// Hash returns the Argon2id hash for the given password and salt
func Hash(password, salt []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, errors.ErrEmptyPassword
	}

	if len(salt) != config.SaltSize {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", errors.ErrInvalidSalt, config.SaltSize, len(salt))
	}

	key := argon2.IDKey(
		password,
		salt,
		config.ArgonTime,
		config.ArgonMemory,
		config.ArgonThreads,
		config.MasterKeySize,
	)

	return key, nil
}

// GetRandomSalt returns a new random salt
func GetRandomSalt(size int) ([]byte, error) {
	salt := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("%w: %v", errors.ErrSaltGeneration, err)
	}
	return salt, nil
}
