// Package header provides functionality for creating, reading, and writing file headers.
package header

import (
	"crypto/hmac"
	"fmt"

	"github.com/hambosto/sweetbyte/internal/utils"
)

// ChecksumVerifier is responsible for verifying the header's checksum.
// The checksum provides a basic, non-cryptographic integrity check of the entire header.
type ChecksumVerifier struct {
	key []byte // The key is used to recompute the expected checksum.
}

// NewChecksumVerifier creates a new ChecksumVerifier with the given key.
func NewChecksumVerifier(key []byte) *ChecksumVerifier {
	return &ChecksumVerifier{key: key}
}

// Verify computes the expected checksum of the header and compares it to the stored checksum.
// It returns an error if the checksums do not match.
func (cv *ChecksumVerifier) Verify(header *Header) error {
	// Recompute the checksum using the same logic as in Protector.
	protector := NewProtector(cv.key)
	expected, err := protector.ComputeChecksum(header)
	if err != nil {
		return fmt.Errorf("failed to compute expected checksum: %w", err)
	}

	// Compare the stored checksum with the recomputed one.
	if header.checksum != expected {
		return fmt.Errorf("checksum mismatch: expected %08x, got %08x", expected, header.checksum)
	}

	return nil
}

// IntegrityVerifier is responsible for verifying the header's integrity hash.
// This hash protects the structural parts of the header from tampering.
type IntegrityVerifier struct {
	key []byte // The key is used for consistency with other verifiers, though not directly used here.
}

// NewIntegrityVerifier creates a new IntegrityVerifier.
func NewIntegrityVerifier(key []byte) *IntegrityVerifier {
	return &IntegrityVerifier{key: key}
}

// Verify computes the expected integrity hash and compares it to the stored hash.
// It uses a secure comparison to prevent timing attacks.
func (iv *IntegrityVerifier) Verify(header *Header) error {
	// Recompute the integrity hash.
	protector := NewProtector(iv.key)
	expected, err := protector.ComputeIntegrityHash(header)
	if err != nil {
		return fmt.Errorf("failed to compute expected integrity hash: %w", err)
	}

	// Securely compare the stored hash with the recomputed one.
	if !utils.SecureCompare(header.integrityHash[:], expected) {
		return fmt.Errorf("integrity hash verification failed - tampering detected")
	}

	return nil
}

// AuthVerifier is responsible for verifying the header's authentication tag.
// The auth tag ensures both integrity and authenticity of the header, given a secret key.
type AuthVerifier struct {
	key []byte // The secret key required to verify the HMAC-based authentication tag.
}

// NewAuthVerifier creates a new AuthVerifier with the given key.
func NewAuthVerifier(key []byte) *AuthVerifier {
	return &AuthVerifier{key: key}
}

// Verify computes the expected authentication tag and compares it to the stored tag.
// It uses a constant-time comparison to prevent timing attacks.
func (av *AuthVerifier) Verify(header *Header) error {
	// A key is mandatory for authentication.
	if len(av.key) == 0 {
		return fmt.Errorf("key required for authentication verification")
	}

	// Recompute the authentication tag.
	protector := NewProtector(av.key)
	expected, err := protector.ComputeAuthTag(header)
	if err != nil {
		return fmt.Errorf("failed to compute expected auth tag: %w", err)
	}

	// Use HMAC's constant-time comparison for security.
	if !hmac.Equal(header.authTag[:], expected) {
		return fmt.Errorf("authentication verification failed - invalid key or tampering detected")
	}

	return nil
}
