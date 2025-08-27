// Package header provides functionality for creating, reading, and writing file headers.
package header

import (
	"crypto/hmac"
	"fmt"

	"github.com/hambosto/sweetbyte/internal/utils"
)

// Verifier orchestrates the entire header verification process.
// It aggregates multiple specialized verifiers to perform a comprehensive check
// of the header's format, integrity, authenticity, and security properties.
type Verifier struct {
	key       []byte
	protector *Protector
}

// NewVerifier creates a new Verifier instance with the given key.
func NewVerifier(key []byte) *Verifier {
	return &Verifier{
		key:       key,
		protector: NewProtector(key),
	}
}

// VerifyAll performs a full suite of verification checks on the header.
// It sequences through format, checksum, integrity, authentication, anti-tampering,
// and security pattern checks, returning an error on the first failure.
func (v *Verifier) VerifyAll(header *Header) error {
	if err := v.verifyFormat(header); err != nil {
		return fmt.Errorf("format verification failed: %w", err)
	}
	if err := v.verifyChecksum(header); err != nil {
		return fmt.Errorf("checksum verification failed: %w", err)
	}
	if err := v.verifyIntegrity(header); err != nil {
		return fmt.Errorf("integrity verification failed: %w", err)
	}
	if err := v.verifyAuth(header); err != nil {
		return fmt.Errorf("authentication verification failed: %w", err)
	}
	if err := v.verifyTampering(header); err != nil {
		return fmt.Errorf("anti-tampering verification failed: %w", err)
	}
	return nil
}

func (v *Verifier) verifyFormat(h *Header) error {
	// Verify that the magic bytes match the expected constant.
	if !utils.SecureCompare(h.magic[:], []byte(MagicBytes)) {
		return fmt.Errorf("invalid magic bytes: expected %s, got %s", MagicBytes, string(h.magic[:]))
	}
	// Verify that the version is supported.
	if h.version == 0 {
		return fmt.Errorf("invalid version: cannot be zero")
	}
	if h.version > CurrentVersion {
		return fmt.Errorf("unsupported version: %d (maximum supported: %d)", h.version, CurrentVersion)
	}
	// Verify that the original size is a non-zero value.
	if h.originalSize == 0 {
		return fmt.Errorf("invalid original size: cannot be zero")
	}
	// Verify that all required security flags are set.
	if !h.HasFlag(FlagEncrypted) {
		return fmt.Errorf("encryption flag not set - header created without maximum security")
	}
	if !h.HasFlag(FlagIntegrityV2) {
		return fmt.Errorf("integrity v2 flag not set - header created without maximum security")
	}
	if !h.HasFlag(FlagAntiTamper) {
		return fmt.Errorf("anti-tamper flag not set - header created without maximum security")
	}
	return nil
}

func (v *Verifier) verifyChecksum(header *Header) error {
	expected, err := v.protector.ComputeChecksum(header)
	if err != nil {
		return fmt.Errorf("failed to compute expected checksum: %w", err)
	}
	if header.checksum != expected {
		return fmt.Errorf("checksum mismatch: expected %08x, got %08x", expected, header.checksum)
	}
	return nil
}

func (v *Verifier) verifyIntegrity(header *Header) error {
	expected, err := v.protector.ComputeIntegrityHash(header)
	if err != nil {
		return fmt.Errorf("failed to compute expected integrity hash: %w", err)
	}
	if !utils.SecureCompare(header.integrityHash[:], expected) {
		return fmt.Errorf("integrity hash verification failed - tampering detected")
	}
	return nil
}

func (v *Verifier) verifyAuth(header *Header) error {
	if len(v.key) == 0 {
		return fmt.Errorf("key required for authentication verification")
	}
	expected, err := v.protector.ComputeAuthTag(header)
	if err != nil {
		return fmt.Errorf("failed to compute expected auth tag: %w", err)
	}
	if !hmac.Equal(header.authTag[:], expected) {
		return fmt.Errorf("authentication verification failed - invalid key or tampering detected")
	}
	return nil
}

func (v *Verifier) verifyTampering(h *Header) error {
	if isAllZeros(h.salt[:]) {
		return fmt.Errorf("invalid salt: all zeros detected - possible tampering")
	}
	if isAllZeros(h.padding[:]) {
		return fmt.Errorf("invalid padding: all zeros detected - possible tampering")
	}
	if isAllZeros(h.integrityHash[:]) {
		return fmt.Errorf("invalid integrity hash: all zeros detected - possible tampering")
	}
	if isAllZeros(h.authTag[:]) {
		return fmt.Errorf("invalid auth tag: all zeros detected - possible tampering")
	}
	return nil
}

func isAllZeros(data []byte) bool {
	zeroData := make([]byte, len(data))
	return utils.SecureCompare(data, zeroData)
}
