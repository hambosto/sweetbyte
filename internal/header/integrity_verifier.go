package header

import (
	"crypto/hmac"
	"fmt"

	"github.com/hambosto/sweetbyte/internal/utils"
)

// ChecksumVerifier verifies header checksums
type ChecksumVerifier struct {
	key []byte
}

// NewChecksumVerifier creates a new ChecksumVerifier
func NewChecksumVerifier(key []byte) *ChecksumVerifier {
	return &ChecksumVerifier{key: key}
}

// Verify verifies the checksum of the header
func (cv *ChecksumVerifier) Verify(header *Header) error {
	protector := NewProtector(cv.key)
	expected, err := protector.ComputeChecksum(header)
	if err != nil {
		return fmt.Errorf("failed to compute expected checksum: %w", err)
	}

	if header.checksum != expected {
		return fmt.Errorf("checksum mismatch: expected %08x, got %08x", expected, header.checksum)
	}

	return nil
}

// IntegrityVerifier verifies header integrity
type IntegrityVerifier struct {
	key []byte
}

// NewIntegrityVerifier creates a new IntegrityVerifier
func NewIntegrityVerifier(key []byte) *IntegrityVerifier {
	return &IntegrityVerifier{key: key}
}

// Verify verifies the integrity of the header
func (iv *IntegrityVerifier) Verify(header *Header) error {
	protector := NewProtector(iv.key)
	expected, err := protector.ComputeIntegrityHash(header)
	if err != nil {
		return fmt.Errorf("failed to compute expected integrity hash: %w", err)
	}

	if !utils.SecureCompare(header.integrityHash[:], expected) {
		return fmt.Errorf("integrity hash verification failed - tampering detected")
	}

	return nil
}

// AuthVerifier verifies header authentication
type AuthVerifier struct {
	key []byte
}

// NewAuthVerifier creates a new AuthVerifier
func NewAuthVerifier(key []byte) *AuthVerifier {
	return &AuthVerifier{key: key}
}

// Verify verifies the authentication of the header
func (av *AuthVerifier) Verify(header *Header) error {
	if len(av.key) == 0 {
		return fmt.Errorf("key required for authentication verification")
	}

	protector := NewProtector(av.key)
	expected, err := protector.ComputeAuthTag(header)
	if err != nil {
		return fmt.Errorf("failed to compute expected auth tag: %w", err)
	}

	if !hmac.Equal(header.authTag[:], expected) {
		return fmt.Errorf("authentication verification failed - invalid key or tampering detected")
	}

	return nil
}
