// Package header manages the secure header of SweetByte encrypted files.
// It defines the header structure, provides mechanisms for its creation, serialization,
// deserialization, and crucial verification processes to ensure data integrity and authenticity.
package header

import (
	"crypto/hmac"
	"fmt"
)

// Verifier is responsible for performing comprehensive validation checks on a Header.
// It ensures the header's format, integrity, authenticity, and adherence to security patterns,
// protecting against corruption and tampering.
type Verifier struct {
	key []byte // The cryptographic key used for HMAC verification.
}

// NewVerifier creates and returns a new Verifier instance with the provided key.
// This key is essential for verifying the HMAC-SHA256 authentication tag.
func NewVerifier(key []byte) *Verifier {
	return &Verifier{
		key: key, // Store the provided key for verification purposes.
	}
}

// VerifyAll orchestrates a series of verification checks on the given Header.
// It performs format, checksum, integrity, authentication, anti-tampering, and security pattern checks.
// The first encountered error will stop the verification process and be returned.
func (v *Verifier) VerifyAll(header *Header) error {
	if err := v.VerifyFormat(header); err != nil { // Verify the basic format and flags of the header.
		return fmt.Errorf("format verification failed: %w", err)
	}

	if err := v.VerifyChecksum(header); err != nil { // Verify the CRC32 checksum for accidental corruption.
		return fmt.Errorf("checksum verification failed: %w", err)
	}

	if err := v.VerifyIntegrity(header); err != nil { // Verify the SHA-256 integrity hash.
		return fmt.Errorf("integrity verification failed: %w", err)
	}

	if err := v.VerifyAuthentication(header); err != nil { // Verify the HMAC-SHA256 authentication tag.
		return fmt.Errorf("authentication verification failed: %w", err)
	}

	if err := v.VerifyAntiTampering(header); err != nil { // Perform additional checks for common tampering patterns.
		return fmt.Errorf("anti-tampering verification failed: %w", err)
	}

	if err := v.VerifySecurityPatterns(header); err != nil { // Check for weak entropy or predictable patterns in sensitive fields.
		return fmt.Errorf("security pattern verification failed: %w", err)
	}

	return nil // Return nil if all verification checks pass successfully.
}

// VerifyFormat checks the basic structural and flag integrity of the header.
// It ensures magic bytes, version, original size, and essential flags are correctly set.
func (v *Verifier) VerifyFormat(h *Header) error {
	if !secureCompare(h.magic[:], []byte(MagicBytes)) { // Error for incorrect magic bytes.
		return fmt.Errorf("invalid magic bytes: expected %s, got %s",
			MagicBytes, string(h.magic[:]))
	}

	// Check if the version is zero (invalid) or an unsupported future version.
	if h.version == 0 { // Error for zero version.
		return fmt.Errorf("invalid version: cannot be zero")
	}
	if h.version > CurrentVersion { // Check if the header version is higher than the supported current version.
		return fmt.Errorf("unsupported version: %d (maximum supported: %d)",
			h.version, CurrentVersion) // Error for unsupported version.
	}

	// Ensure the original size is not zero, as a zero-sized file is invalid.
	if h.originalSize == 0 { // Error for zero original size.
		return fmt.Errorf("invalid original size: cannot be zero")
	}

	// Define a reasonable maximum file size to prevent processing excessively large or malicious files.
	const maxFileSize = 1024 * 1024 * 1024 * 1024 // 1 TB
	if h.originalSize > maxFileSize {             // Check if the original file size exceeds the maximum allowed.
		return fmt.Errorf("unreasonable file size: %d bytes (max: %d)",
			h.originalSize, maxFileSize) // Error for unreasonable file size.
	}

	// Verify that essential security flags are set, indicating the header was created with maximum security.
	if !h.HasFlag(FlagEncrypted) { // Ensure the encryption flag is set.
		return fmt.Errorf("encryption flag not set - header created without maximum security")
	}
	if !h.HasFlag(FlagIntegrityV2) { // Ensure the integrity v2 flag is set.
		return fmt.Errorf("integrity v2 flag not set - header created without maximum security")
	}
	if !h.HasFlag(FlagAntiTamper) { // Ensure the anti-tamper flag is set.
		return fmt.Errorf("anti-tamper flag not set - header created without maximum security")
	}

	return nil // Return nil if all format checks pass.
}

// VerifyChecksum recomputes the CRC32 checksum of the header and compares it to the stored checksum.
// A mismatch indicates accidental data corruption in the header.
func (v *Verifier) VerifyChecksum(header *Header) error {
	protector := NewProtector(v.key)                   // Create a temporary Protector to compute the expected checksum.
	expected, err := protector.ComputeChecksum(header) // Compute the checksum based on the current header data.
	if err != nil {
		return fmt.Errorf("failed to compute expected checksum: %w", err)
	}

	if header.checksum != expected { // Compare the stored checksum with the newly computed one.
		return fmt.Errorf("checksum mismatch: expected %08x, got %08x", expected, header.checksum) // Return error for checksum mismatch.
	}

	return nil // Return nil if checksums match.
}

// VerifyIntegrity recomputes the SHA-256 integrity hash of the header's structural data
// and compares it to the stored hash. A mismatch indicates potential tampering.
func (v *Verifier) VerifyIntegrity(header *Header) error {
	protector := NewProtector(v.key)                        // Create a temporary Protector to compute the expected integrity hash.
	expected, err := protector.ComputeIntegrityHash(header) // Compute the integrity hash based on structural data.
	if err != nil {
		return fmt.Errorf("failed to compute expected integrity hash: %w", err)
	}

	if !secureCompare(header.integrityHash[:], expected) { // Perform a constant-time comparison of the hashes.
		return fmt.Errorf("integrity hash verification failed - tampering detected") // Return error for hash mismatch.
	}

	return nil // Return nil if integrity hashes match.
}

// VerifyAuthentication recomputes the HMAC-SHA256 authentication tag of the header
// and compares it to the stored tag. A mismatch strongly indicates tampering or an incorrect key.
func (v *Verifier) VerifyAuthentication(header *Header) error {
	if len(v.key) == 0 { // Ensure a key is provided for authentication verification.
		return fmt.Errorf("key required for authentication verification")
	}

	protector := NewProtector(v.key)                  // Create a temporary Protector to compute the expected authentication tag.
	expected, err := protector.ComputeAuthTag(header) // Compute the authentication tag.
	if err != nil {
		return fmt.Errorf("failed to compute expected auth tag: %w", err)
	}

	if !hmac.Equal(header.authTag[:], expected) { // Use hmac.Equal for constant-time comparison of authentication tags.
		return fmt.Errorf("authentication verification failed - invalid key or tampering detected") // Return error for tag mismatch.
	}

	return nil // Return nil if authentication tags match.
}

// VerifyAntiTampering performs checks on sensitive header fields (salt, padding, hashes, tags)
// to ensure they are not filled with zeros, which could indicate a malicious or corrupt header.
func (v *Verifier) VerifyAntiTampering(h *Header) error {
	// Check if the salt is all zeros, indicating a potential compromise.
	zeroSalt := make([]byte, SaltSize)
	if secureCompare(h.salt[:], zeroSalt) {
		return fmt.Errorf("invalid salt: all zeros detected - possible tampering") // Error for zero salt.
	}

	// Check if the padding is all zeros, which could be a sign of tampering.
	zeroPadding := make([]byte, PaddingSize)
	if secureCompare(h.padding[:], zeroPadding) {
		return fmt.Errorf("invalid padding: all zeros detected - possible tampering") // Error for zero padding.
	}

	// Check if the integrity hash is all zeros.
	zeroHash := make([]byte, IntegrityHashSize)
	if secureCompare(h.integrityHash[:], zeroHash) {
		return fmt.Errorf("invalid integrity hash: all zeros detected") // Error for zero integrity hash.
	}

	// Check if the authentication tag is all zeros.
	zeroAuth := make([]byte, AuthTagSize)
	if secureCompare(h.authTag[:], zeroAuth) {
		return fmt.Errorf("invalid auth tag: all zeros detected") // Error for zero authentication tag.
	}

	return nil // Return nil if anti-tampering checks pass.
}

// VerifySecurityPatterns checks for suspicious patterns in sensitive header fields (salt and padding)
// such as repeating bytes or simple sequential patterns, and also validates their entropy levels.
func (v *Verifier) VerifySecurityPatterns(h *Header) error {
	// Check for repeating byte patterns in salt.
	if err := v.checkForRepeatingBytes(h.salt[:], "salt"); err != nil {
		return err
	}

	// Check for repeating byte patterns in padding.
	if err := v.checkForRepeatingBytes(h.padding[:], "padding"); err != nil {
		return err
	}

	// Validate the entropy level of the salt.
	if err := v.validateEntropy(h.salt[:], "salt", SaltSize/4); err != nil {
		return err
	}

	// Validate the entropy level of the padding.
	if err := v.validateEntropy(h.padding[:], "padding", PaddingSize/4); err != nil {
		return err
	}

	return nil // Return nil if all security pattern checks pass.
}

// checkForRepeatingBytes checks if a given byte slice consists of all identical bytes or a simple sequential pattern.
// Such patterns in cryptographic fields can indicate weak random number generation or tampering.
func (v *Verifier) checkForRepeatingBytes(data []byte, fieldName string) error {
	if len(data) < 4 { // Skip checks for very small data slices.
		return nil
	}

	// Check if all bytes in the data slice are the same.
	first := data[0]
	allSame := true
	for _, b := range data {
		if b != first {
			allSame = false
			break
		}
	}
	if allSame { // If all bytes are identical, report a suspicious pattern.
		return fmt.Errorf("suspicious %s: all bytes identical (0x%02x) - possible tampering",
			fieldName, first)
	}

	// Check for simple ascending or descending sequential patterns.
	if v.hasSimplePattern(data) {
		return fmt.Errorf("suspicious %s: sequential pattern detected - possible tampering", fieldName)
	}

	return nil // Return nil if no suspicious repeating or sequential patterns are found.
}

// hasSimplePattern checks if the initial part of a byte slice exhibits a simple ascending or descending sequence.
// This is a quick check for predictable or non-random data.
func (v *Verifier) hasSimplePattern(data []byte) bool {
	if len(data) < 4 { // Require at least 4 bytes to check for a pattern.
		return false
	}

	// Check for an ascending sequence (e.g., 0x01, 0x02, 0x03...).
	ascending := true
	for i := 1; i < len(data) && i < 8; i++ { // Check up to 8 bytes for efficiency.
		if data[i] != data[i-1]+1 {
			ascending = false
			break
		}
	}

	// Check for a descending sequence (e.g., 0xFF, 0xFE, 0xFD...).
	descending := true
	for i := 1; i < len(data) && i < 8; i++ { // Check up to 8 bytes for efficiency.
		if data[i] != data[i-1]-1 {
			descending = false
			break
		}
	}

	return ascending || descending // Return true if either ascending or descending pattern is found.
}

// validateEntropy checks if the given byte slice has a sufficient number of unique bytes,
// indicating adequate entropy. Low entropy in cryptographic fields can suggest weak generation.
func (v *Verifier) validateEntropy(data []byte, fieldName string, minUnique int) error {
	uniqueBytes := make(map[byte]bool) // Use a map to count unique bytes.
	for _, b := range data {
		uniqueBytes[b] = true
	}

	if len(uniqueBytes) < minUnique { // Compare the count of unique bytes to the minimum required entropy.
		return fmt.Errorf("insufficient entropy in %s: only %d unique bytes (minimum: %d) - possible weak generation",
			fieldName, len(uniqueBytes), minUnique) // Return error for insufficient entropy.
	}

	return nil // Return nil if entropy is sufficient.
}
