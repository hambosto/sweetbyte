package header

import (
	"crypto/hmac"
	"fmt"
)

// Verifier handles comprehensive header verification
type Verifier struct {
	key []byte
}

// NewVerifier creates a new verifier instance
func NewVerifier(key []byte) *Verifier {
	return &Verifier{
		key: key,
	}
}

// VerifyAll performs maximum security verification of the header
func (v *Verifier) VerifyAll(header *Header) error {
	// Level 1: Format and structure validation
	if err := v.VerifyFormat(header); err != nil {
		return fmt.Errorf("format verification failed: %w", err)
	}

	// Level 2: Quick corruption detection
	if err := v.VerifyChecksum(header); err != nil {
		return fmt.Errorf("checksum verification failed: %w", err)
	}

	// Level 3: Cryptographic integrity verification
	if err := v.VerifyIntegrity(header); err != nil {
		return fmt.Errorf("integrity verification failed: %w", err)
	}

	// Level 4: Authentication verification
	if err := v.VerifyAuthentication(header); err != nil {
		return fmt.Errorf("authentication verification failed: %w", err)
	}

	// Level 5: Anti-tampering verification
	if err := v.VerifyAntiTampering(header); err != nil {
		return fmt.Errorf("anti-tampering verification failed: %w", err)
	}

	// Level 6: Security pattern analysis
	if err := v.VerifySecurityPatterns(header); err != nil {
		return fmt.Errorf("security pattern verification failed: %w", err)
	}

	return nil
}

// VerifyFormat validates basic header format and structure
func (v *Verifier) VerifyFormat(h *Header) error {
	// Validate magic bytes
	if !secureCompare(h.magic[:], []byte(MagicBytes)) {
		return fmt.Errorf("invalid magic bytes: expected %s, got %s",
			MagicBytes, string(h.magic[:]))
	}

	// Validate version
	if h.version == 0 {
		return fmt.Errorf("invalid version: cannot be zero")
	}
	if h.version > CurrentVersion {
		return fmt.Errorf("unsupported version: %d (maximum supported: %d)",
			h.version, CurrentVersion)
	}

	// Validate original size
	if h.originalSize == 0 {
		return fmt.Errorf("invalid original size: cannot be zero")
	}

	// Check for reasonable file size limits (1TB max)
	const maxFileSize = 1024 * 1024 * 1024 * 1024 // 1TB
	if h.originalSize > maxFileSize {
		return fmt.Errorf("unreasonable file size: %d bytes (max: %d)",
			h.originalSize, maxFileSize)
	}

	// Validate required flags are set for maximum security
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

// VerifyChecksum validates the CRC32 checksum
func (v *Verifier) VerifyChecksum(header *Header) error {
	protector := NewProtector(v.key)
	expected, err := protector.ComputeChecksum(header)
	if err != nil {
		return fmt.Errorf("failed to compute expected checksum: %w", err)
	}

	if header.checksum != expected {
		return fmt.Errorf("checksum mismatch: expected %08x, got %08x",
			expected, header.checksum)
	}

	return nil
}

// VerifyIntegrity validates the SHA-256 integrity hash
func (v *Verifier) VerifyIntegrity(header *Header) error {
	protector := NewProtector(v.key)
	expected, err := protector.ComputeIntegrityHash(header)
	if err != nil {
		return fmt.Errorf("failed to compute expected integrity hash: %w", err)
	}

	if !secureCompare(header.integrityHash[:], expected) {
		return fmt.Errorf("integrity hash verification failed - tampering detected")
	}

	return nil
}

// VerifyAuthentication validates the HMAC authentication tag
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

// VerifyAntiTampering performs anti-tampering checks
func (v *Verifier) VerifyAntiTampering(h *Header) error {
	// Check for all-zero salt (indicates tampering or weak generation)
	zeroSalt := make([]byte, SaltSize)
	if secureCompare(h.salt[:], zeroSalt) {
		return fmt.Errorf("invalid salt: all zeros detected - possible tampering")
	}

	// Check for all-zero padding (should be random)
	zeroPadding := make([]byte, PaddingSize)
	if secureCompare(h.padding[:], zeroPadding) {
		return fmt.Errorf("invalid padding: all zeros detected - possible tampering")
	}

	// Check for all-zero integrity hash
	zeroHash := make([]byte, IntegrityHashSize)
	if secureCompare(h.integrityHash[:], zeroHash) {
		return fmt.Errorf("invalid integrity hash: all zeros detected")
	}

	// Check for all-zero auth tag
	zeroAuth := make([]byte, AuthTagSize)
	if secureCompare(h.authTag[:], zeroAuth) {
		return fmt.Errorf("invalid auth tag: all zeros detected")
	}

	return nil
}

// VerifySecurityPatterns performs advanced security pattern analysis
func (v *Verifier) VerifySecurityPatterns(h *Header) error {
	// Check for repetitive patterns in salt
	if err := v.checkForRepeatingBytes(h.salt[:], "salt"); err != nil {
		return err
	}

	// Check for repetitive patterns in padding
	if err := v.checkForRepeatingBytes(h.padding[:], "padding"); err != nil {
		return err
	}

	// Validate entropy in random fields
	if err := v.validateEntropy(h.salt[:], "salt", SaltSize/4); err != nil {
		return err
	}

	if err := v.validateEntropy(h.padding[:], "padding", PaddingSize/4); err != nil {
		return err
	}

	return nil
}

// checkForRepeatingBytes detects suspicious repeating byte patterns
func (v *Verifier) checkForRepeatingBytes(data []byte, fieldName string) error {
	if len(data) < 4 {
		return nil
	}

	// Check for all same bytes
	first := data[0]
	allSame := true
	for _, b := range data {
		if b != first {
			allSame = false
			break
		}
	}
	if allSame {
		return fmt.Errorf("suspicious %s: all bytes identical (0x%02x) - possible tampering",
			fieldName, first)
	}

	// Check for simple sequential patterns
	if v.hasSimplePattern(data) {
		return fmt.Errorf("suspicious %s: sequential pattern detected - possible tampering", fieldName)
	}

	return nil
}

// hasSimplePattern detects simple sequential patterns
func (v *Verifier) hasSimplePattern(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	// Check for ascending pattern
	ascending := true
	for i := 1; i < len(data) && i < 8; i++ {
		if data[i] != data[i-1]+1 {
			ascending = false
			break
		}
	}

	// Check for descending pattern
	descending := true
	for i := 1; i < len(data) && i < 8; i++ {
		if data[i] != data[i-1]-1 {
			descending = false
			break
		}
	}

	return ascending || descending
}

// validateEntropy validates minimum entropy in a field
func (v *Verifier) validateEntropy(data []byte, fieldName string, minUnique int) error {
	uniqueBytes := make(map[byte]bool)
	for _, b := range data {
		uniqueBytes[b] = true
	}

	if len(uniqueBytes) < minUnique {
		return fmt.Errorf("insufficient entropy in %s: only %d unique bytes (minimum: %d) - possible weak generation",
			fieldName, len(uniqueBytes), minUnique)
	}

	return nil
}
