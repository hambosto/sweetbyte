// Package keys provides utilities for cryptographic key derivation and secure salt generation.
// It uses Argon2id, a robust key derivation function, to transform passwords into strong cryptographic keys.
package keys

import (
	"crypto/rand"
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/config"
	"golang.org/x/crypto/argon2"
)

const (
	// ArgonTime defines the number of iterations for Argon2id.
	// A higher value increases resistance to time-memory trade-off attacks but also increases computation time.
	ArgonTime uint32 = 4
	// ArgonMemory defines the memory cost for Argon2id in kilobytes.
	// A higher value increases memory usage, making brute-force attacks more expensive.
	ArgonMemory uint32 = 128 * 1024 // 128 MB
	// ArgonThreads defines the number of parallel threads (lanes) for Argon2id.
	// This parameter leverages multiple CPU cores, improving performance on multi-core systems.
	ArgonThreads uint8 = 4
)

// Hash derives a cryptographic key from a password and a salt using Argon2id.
// This function is designed to be computationally intensive to resist brute-force attacks.
// It returns a key of `config.MasterKeySize` bytes.
func Hash(password, salt []byte) ([]byte, error) {
	if len(password) == 0 {
		return nil, fmt.Errorf("password cannot be empty") // Return error if password is empty.
	}

	if len(salt) != config.SaltSize { // Validate the salt length.
		return nil, fmt.Errorf("expected %d bytes, got %d", config.SaltSize, len(salt)) // Return error for invalid salt size.
	}

	// Perform key derivation using Argon2id with predefined parameters.
	key := argon2.IDKey(
		password,             // The user's password.
		salt,                 // A unique, random salt to prevent precomputation attacks.
		ArgonTime,            // Time cost (number of iterations).
		ArgonMemory,          // Memory cost (in KB).
		ArgonThreads,         // Number of parallel threads.
		config.MasterKeySize, // Desired length of the derived key.
	)

	return key, nil // Return the derived key.
}

// GetRandomSalt generates a cryptographically secure random salt of the specified size.
// This salt is crucial for key derivation to ensure that the same password generates a unique key each time,
// protecting against rainbow table attacks.
func GetRandomSalt(size int) ([]byte, error) {
	salt := make([]byte, size)                                // Create a byte slice of the desired size for the salt.
	if _, err := io.ReadFull(rand.Reader, salt); err != nil { // Fill the slice with cryptographically strong random bytes.
		return nil, fmt.Errorf("failed to generate salt: %w", err) // Return error if random bytes generation fails.
	}
	return salt, nil // Return the generated random salt.
}
