package derive

import (
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	ArgonTime    = 8
	ArgonMemory  = 1 << 20
	ArgonThreads = 8
	ArgonKeyLen  = 64
	ArgonSaltLen = 32
)

func Hash(password, salt []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be empty")
	}

	if len(salt) != ArgonSaltLen {
		return nil, fmt.Errorf("expected %d bytes, got %d", ArgonSaltLen, len(salt))
	}

	key := argon2.IDKey(
		password,
		salt,
		ArgonTime,
		ArgonMemory,
		ArgonThreads,
		ArgonKeyLen,
	)

	return key, nil
}

func GetRandomBytes(size int) ([]byte, error) {
	salt := make([]byte, size)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, fmt.Errorf("failed to generate salt: %w", err)
	}
	return salt, nil
}
