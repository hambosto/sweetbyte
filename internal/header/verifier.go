// Package header provides functionality for creating, reading, and writing file headers.
package header

import (
	"crypto/hmac"
	"fmt"

	"github.com/hambosto/sweetbyte/internal/utils"
)

// Verifier is responsible for verifying the header's integrity and authenticity.
type Verifier struct {
	key []byte
}

// NewVerifier creates a new Verifier instance with the given key.
func NewVerifier(key []byte) *Verifier {
	return &Verifier{key: key}
}

// Verify performs a full suite of verification checks on the header.
func (v *Verifier) Verify(h *Header) error {
	if err := v.verifyFormat(h); err != nil {
		return fmt.Errorf("format verification failed: %w", err)
	}
	if err := v.verifyTampering(h); err != nil {
		return fmt.Errorf("tamper verification failed: %w", err)
	}
	if err := v.verifyAuthTag(h); err != nil {
		return fmt.Errorf("authentication verification failed: %w", err)
	}
	return nil
}

func (v *Verifier) verifyFormat(h *Header) error {
	if !utils.SecureCompare(h.magic[:], []byte(MagicBytes)) {
		return fmt.Errorf("invalid magic bytes: expected %s, got %s", MagicBytes, string(h.magic[:]))
	}
	if h.version == 0 {
		return fmt.Errorf("invalid version: cannot be zero")
	}
	if h.version > CurrentVersion {
		return fmt.Errorf("unsupported version: %d (maximum supported: %d)", h.version, CurrentVersion)
	}
	if h.originalSize == 0 {
		return fmt.Errorf("invalid original size: cannot be zero")
	}
	return nil
}

func (v *Verifier) verifyTampering(h *Header) error {
	if isAllZeros(h.salt[:]) {
		return fmt.Errorf("invalid salt: all zeros detected")
	}
	if isAllZeros(h.padding[:]) {
		return fmt.Errorf("invalid padding: all zeros detected")
	}
	if isAllZeros(h.authTag[:]) {
		return fmt.Errorf("invalid auth tag: all zeros detected")
	}
	return nil
}

func (v *Verifier) verifyAuthTag(h *Header) error {
	if len(v.key) == 0 {
		return fmt.Errorf("key required for authentication verification")
	}
	protector := NewProtector(v.key)
	expectedTag, err := protector.ComputeAuthTag(h)
	if err != nil {
		return fmt.Errorf("failed to compute expected auth tag: %w", err)
	}
	if !hmac.Equal(h.authTag[:], expectedTag) {
		return fmt.Errorf("authentication failed: invalid key or tampered header")
	}
	return nil
}

func isAllZeros(data []byte) bool {
	for _, b := range data {
		if b != 0 {
			return false
		}
	}
	return true
}
