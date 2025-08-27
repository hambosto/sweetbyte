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
	key []byte // The secret key used for cryptographic verification (checksum, integrity, auth).
}

// NewVerifier creates a new Verifier instance with the given key.
func NewVerifier(key []byte) *Verifier {
	return &Verifier{key: key}
}

// VerifyAll performs a full suite of verification checks on the header.
// It sequences through format, checksum, integrity, authentication, anti-tampering,
// and security pattern checks, returning an error on the first failure.
func (v *Verifier) VerifyAll(header *Header) error {
	// Instantiate all the necessary verifier components.
	formatVerifier := NewFormatVerifier()
	checksumVerifier := NewChecksumVerifier(v.key)
	integrityVerifier := NewIntegrityVerifier(v.key)
	authVerifier := NewAuthVerifier(v.key)
	tamperVerifier := NewTamperVerifier()

	// Execute format verification
	if err := formatVerifier.Verify(header); err != nil {
		return fmt.Errorf("format verification failed: %w", err)
	}

	// Execute checksum verification
	if err := checksumVerifier.Verify(header); err != nil {
		return fmt.Errorf("checksum verification failed: %w", err)
	}

	// Execute integrity verification
	if err := integrityVerifier.Verify(header); err != nil {
		return fmt.Errorf("integrity verification failed: %w", err)
	}

	// Execute authentication verification
	if err := authVerifier.Verify(header); err != nil {
		return fmt.Errorf("authentication verification failed: %w", err)
	}

	// Execute anti-tampering verification
	if err := tamperVerifier.Verify(header); err != nil {
		return fmt.Errorf("anti-tampering verification failed: %w", err)
	}

	return nil
}

// FormatVerifier is responsible for ensuring that a header conforms to the basic structural and format rules.
// This includes checks for magic bytes, version, and other fundamental fields.
// It acts as the first line of defense in validating a header's structure.
type FormatVerifier struct{}

// NewFormatVerifier creates and returns a new FormatVerifier instance.
func NewFormatVerifier() *FormatVerifier {
	return &FormatVerifier{}
}

// Verify runs a series of checks to validate the header's overall format.
// It aggregates individual verification functions for a comprehensive format check.
// Returns an error if any of the format verification checks fail.
func (fv *FormatVerifier) Verify(h *Header) error {
	// Verify that the magic bytes match the expected constant.
	if err := fv.verifyMagicBytes(h); err != nil {
		return err
	}
	// Verify that the version is supported.
	if err := fv.verifyVersion(h); err != nil {
		return err
	}
	// Verify that the original size is a non-zero value.
	if err := fv.verifyOriginalSize(h); err != nil {
		return err
	}
	// Verify that all required security flags are set.
	if err := fv.verifySecurityFlags(h); err != nil {
		return err
	}
	return nil
}

// verifyMagicBytes checks if the header's magic bytes match the predefined constant.
// This is a crucial first check to identify the file type.
func (fv *FormatVerifier) verifyMagicBytes(h *Header) error {
	if !utils.SecureCompare(h.magic[:], []byte(MagicBytes)) {
		return fmt.Errorf("invalid magic bytes: expected %s, got %s", MagicBytes, string(h.magic[:]))
	}
	return nil
}

// verifyVersion ensures the header's version is valid and supported.
// It checks that the version is not zero and does not exceed the current application version.
func (fv *FormatVerifier) verifyVersion(h *Header) error {
	if h.version == 0 {
		return fmt.Errorf("invalid version: cannot be zero")
	}
	if h.version > CurrentVersion {
		return fmt.Errorf("unsupported version: %d (maximum supported: %d)", h.version, CurrentVersion)
	}
	return nil
}

// verifyOriginalSize checks that the original size of the file is greater than zero.
func (fv *FormatVerifier) verifyOriginalSize(h *Header) error {
	if h.originalSize == 0 {
		return fmt.Errorf("invalid original size: cannot be zero")
	}
	return nil
}

// verifySecurityFlags ensures that all essential security-related flags are set in the header.
// This enforces a baseline of security for all processed files.
func (fv *FormatVerifier) verifySecurityFlags(h *Header) error {
	if !h.HasFlag(FlagEncrypted) {
		return fmt.Errorf("encryption flag not set - header created without maximum security")
	}

	// Check integrity v2 flag
	if !h.HasFlag(FlagIntegrityV2) {
		return fmt.Errorf("integrity v2 flag not set - header created without maximum security")
	}

	// Check anti-tamper flag
	if !h.HasFlag(FlagAntiTamper) {
		return fmt.Errorf("anti-tamper flag not set - header created without maximum security")
	}

	return nil
}

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

// TamperVerifier checks for obvious signs of tampering, such as all-zero fields.
// This verifier acts as a simple, fast check for uninitialized or maliciously cleared data.
type TamperVerifier struct{}

// NewTamperVerifier creates a new TamperVerifier instance.
func NewTamperVerifier() *TamperVerifier {
	return &TamperVerifier{}
}

// Verify checks critical security fields in the header to ensure they are not all zeros.
// An all-zero field can indicate a failure in generation or a simple form of tampering.
func (tv *TamperVerifier) Verify(h *Header) error {
	// Check salt field
	if tv.isAllZeros(h.salt[:]) {
		return fmt.Errorf("invalid salt: all zeros detected - possible tampering")
	}

	// Check padding field
	if tv.isAllZeros(h.padding[:]) {
		return fmt.Errorf("invalid padding: all zeros detected - possible tampering")
	}

	// Check integrity hash field
	if tv.isAllZeros(h.integrityHash[:]) {
		return fmt.Errorf("invalid integrity hash: all zeros detected - possible tampering")
	}

	// Check auth tag field
	if tv.isAllZeros(h.authTag[:]) {
		return fmt.Errorf("invalid auth tag: all zeros detected - possible tampering")
	}

	return nil
}

// isAllZeros performs a secure comparison of a byte slice against an all-zero slice of the same length.
func (tv *TamperVerifier) isAllZeros(data []byte) bool {
	zeroData := make([]byte, len(data))
	return utils.SecureCompare(data, zeroData)
}
