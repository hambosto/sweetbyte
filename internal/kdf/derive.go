package kdf

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/config"
	"golang.org/x/crypto/argon2"
)

const (
	ArgonTime    uint32 = 8
	ArgonMemory  uint32 = 128 * 1024
	ArgonThreads uint8  = 8
)

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

func GetRandomSalt(size int) ([]byte, error) {
	salt := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}
