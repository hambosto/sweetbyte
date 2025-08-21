// Package header provides functionality for creating, reading, and writing file headers.
package header

import (
	"crypto/hmac"
	"fmt"

	"github.com/hambosto/sweetbyte/internal/utils"
)

// Verifier verifies the integrity and authenticity of a header.
type Verifier struct {
	key []byte
}

// NewVerifier creates a new Verifier.
func NewVerifier(key []byte) *Verifier {
	return &Verifier{
		key: key,
	}
}

// VerifyAll performs all verification checks on the header.
func (v *Verifier) VerifyAll(header *Header) error {
	// Verify the format of the header.
	if err := v.VerifyFormat(header); err != nil {
		return fmt.Errorf("format verification failed: %w", err)
	}

	// Verify the checksum of the header.
	if err := v.VerifyChecksum(header); err != nil {
		return fmt.Errorf("checksum verification failed: %w", err)
	}

	// Verify the integrity of the header.
	if err := v.VerifyIntegrity(header); err != nil {
		return fmt.Errorf("integrity verification failed: %w", err)
	}

	// Verify the authentication of the header.
	if err := v.VerifyAuthentication(header); err != nil {
		return fmt.Errorf("authentication verification failed: %w", err)
	}

	// Verify the anti-tampering measures of the header.
	if err := v.VerifyAntiTampering(header); err != nil {
		return fmt.Errorf("anti-tampering verification failed: %w", err)
	}

	// Verify the security patterns of the header.
	if err := v.VerifySecurityPatterns(header); err != nil {
		return fmt.Errorf("security pattern verification failed: %w", err)
	}

	return nil
}

// VerifyFormat verifies the format of the header.
func (v *Verifier) VerifyFormat(h *Header) error {
	// Verify the magic bytes.
	if !utils.SecureCompare(h.magic[:], []byte(MagicBytes)) {
		return fmt.Errorf("invalid magic bytes: expected %s, got %s",
			MagicBytes, string(h.magic[:]))
	}

	// Verify the version.
	if h.version == 0 {
		return fmt.Errorf("invalid version: cannot be zero")
	}

	if h.version > CurrentVersion {
		return fmt.Errorf("unsupported version: %d (maximum supported: %d)", h.version, CurrentVersion)
	}

	// Verify the original size.
	if h.originalSize == 0 {
		return fmt.Errorf("invalid original size: cannot be zero")
	}

	// Verify the security flags.
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

// VerifyChecksum verifies the checksum of the header.
func (v *Verifier) VerifyChecksum(header *Header) error {
	protector := NewProtector(v.key)
	expected, err := protector.ComputeChecksum(header)
	if err != nil {
		return fmt.Errorf("failed to compute expected checksum: %w", err)
	}

	if header.checksum != expected {
		return fmt.Errorf("checksum mismatch: expected %08x, got %08x", expected, header.checksum)
	}

	return nil
}

// VerifyIntegrity verifies the integrity of the header.
func (v *Verifier) VerifyIntegrity(header *Header) error {
	protector := NewProtector(v.key)
	expected, err := protector.ComputeIntegrityHash(header)
	if err != nil {
		return fmt.Errorf("failed to compute expected integrity hash: %w", err)
	}

	if !utils.SecureCompare(header.integrityHash[:], expected) {
		return fmt.Errorf("integrity hash verification failed - tampering detected")
	}

	return nil
}

// VerifyAuthentication verifies the authentication of the header.
func (v *Verifier) VerifyAuthentication(header *Header) error {
	if len(v.key) == 0 {
		return fmt.Errorf("key required for authentication verification")
	}

	protector := NewProtector(v.key)
	expected, err := protector.ComputeAuthTag(header)
	if err != nil {
		return fmt.Errorf("failed to compute expected auth tag: %w", err)
	}

	if !hmac.Equal(header.authTag[:], expected) {
		return fmt.Errorf("authentication verification failed - invalid key or tampering detected")
	}

	return nil
}

// VerifyAntiTampering verifies the anti-tampering measures of the header.
func (v *Verifier) VerifyAntiTampering(h *Header) error {
	// Check for all-zero fields.
	zeroSalt := make([]byte, SaltSize)
	if utils.SecureCompare(h.salt[:], zeroSalt) {
		return fmt.Errorf("invalid salt: all zeros detected - possible tampering")
	}

	zeroPadding := make([]byte, PaddingSize)
	if utils.SecureCompare(h.padding[:], zeroPadding) {
		return fmt.Errorf("invalid padding: all zeros detected - possible tampering")
	}

	zeroHash := make([]byte, IntegrityHashSize)
	if utils.SecureCompare(h.integrityHash[:], zeroHash) {
		return fmt.Errorf("invalid integrity hash: all zeros detected")
	}

	zeroAuth := make([]byte, AuthTagSize)
	if utils.SecureCompare(h.authTag[:], zeroAuth) {
		return fmt.Errorf("invalid auth tag: all zeros detected")
	}

	return nil
}

// VerifySecurityPatterns verifies the security patterns of the header.
func (v *Verifier) VerifySecurityPatterns(h *Header) error {
	// Check for repeating bytes in the salt and padding.
	if err := v.checkForRepeatingBytes(h.salt[:], "salt"); err != nil {
		return err
	}

	if err := v.checkForRepeatingBytes(h.padding[:], "padding"); err != nil {
		return err
	}

	// Validate the entropy of the salt and padding.
	if err := v.validateEntropy(h.salt[:], "salt", SaltSize/4); err != nil {
		return err
	}

	if err := v.validateEntropy(h.padding[:], "padding", PaddingSize/4); err != nil {
		return err
	}

	return nil
}

// checkForRepeatingBytes checks for repeating bytes in a byte slice.
func (v *Verifier) checkForRepeatingBytes(data []byte, fieldName string) error {
	if len(data) < 4 {
		return nil
	}

	// Check if all bytes are the same.
	first := data[0]
	allSame := true
	for _, b := range data {
		if b != first {
			allSame = false
			break
		}
	}

	if allSame {
		return fmt.Errorf("suspicious %s: all bytes identical (0x%02x) - possible tampering", fieldName, first)
	}

	// Check for simple patterns.
	if v.hasSimplePattern(data) {
		return fmt.Errorf("suspicious %s: sequential pattern detected - possible tampering", fieldName)
	}

	return nil
}

// hasSimplePattern checks for simple ascending or descending patterns in a byte slice.
func (v *Verifier) hasSimplePattern(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	// Check for ascending pattern.
	ascending := true
	for i := 1; i < len(data) && i < 8; i++ {
		if data[i] != data[i-1]+1 {
			ascending = false
			break
		}
	}

	// Check for descending pattern.
	descending := true
	for i := 1; i < len(data) && i < 8; i++ {
		if data[i] != data[i-1]-1 {
			descending = false
			break
		}
	}

	return ascending || descending
}

// validateEntropy validates the entropy of a byte slice.
func (v *Verifier) validateEntropy(data []byte, fieldName string, minUnique int) error {
	uniqueBytes := make(map[byte]bool)
	for _, b := range data {
		uniqueBytes[b] = true
	}

	if len(uniqueBytes) < minUnique {
		return fmt.Errorf("insufficient entropy in %s: only %d unique bytes (minimum: %d) - possible weak generation", fieldName, len(uniqueBytes), minUnique)
	}

	return nil
}
