package header

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"hash/crc32"
	"io"

	"github.com/hambosto/sweetbyte/internal/utils"
)

// Verify checks the integrity and authenticity of the header using a provided key.
// It runs a series of verification checks, including format, checksum, integrity,
// authentication, and tampering. If any check fails, it returns an error.
func (h *Header) Verify(key []byte) error {
	// A list of verifier functions to be executed sequentially.
	verifiers := []func(*Header, []byte) error{
		verifyFormat,
		verifyChecksum,
		verifyIntegrity,
		verifyAuth,
		verifyTampering,
	}

	// Execute each verifier. If any of them returns an error, wrap it and return immediately.
	for _, verifier := range verifiers {
		if err := verifier(h, key); err != nil {
			return fmt.Errorf("header verification failed: %w", err)
		}
	}
	return nil
}

// computeProtection calculates and sets the integrity hash, authentication tag, and checksum for the header.
// This function is called when a new header is created to ensure it is protected.
func computeProtection(h *Header, key []byte) error {
	// Compute and set the integrity hash.
	hash, err := computeIntegrityHash(h)
	if err != nil {
		return fmt.Errorf("integrity hash computation failed: %w", err)
	}
	copy(h.integrityHash[:], hash)

	// Compute and set the authentication tag.
	tag, err := computeAuthTag(h, key)
	if err != nil {
		return fmt.Errorf("auth tag computation failed: %w", err)
	}
	copy(h.authTag[:], tag)

	// Compute and set the checksum.
	checksum, err := computeChecksum(h)
	if err != nil {
		return fmt.Errorf("checksum computation failed: %w", err)
	}
	h.checksum = checksum

	return nil
}

// computeIntegrityHash calculates the SHA-256 hash of the header's structural data.
// This hash ensures that the primary metadata of the header has not been tampered with.
func computeIntegrityHash(h *Header) ([]byte, error) {
	hasher := sha256.New()
	if err := writeStructuralData(hasher, h); err != nil {
		return nil, fmt.Errorf("failed to write structural data: %w", err)
	}
	return hasher.Sum(nil), nil
}

// computeAuthTag calculates the HMAC-SHA256 authentication tag for the header.
// This tag verifies the authenticity and integrity of the header using a secret key.
func computeAuthTag(h *Header, key []byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("key cannot be empty")
	}

	// Create a new HMAC with SHA-256.
	mac := hmac.New(sha256.New, key)

	// Write the structural data to the HMAC.
	if err := writeStructuralData(mac, h); err != nil {
		return nil, fmt.Errorf("failed to write structural data: %w", err)
	}

	// Include the integrity hash and padding in the HMAC to protect them from tampering.
	if _, err := mac.Write(h.integrityHash[:]); err != nil {
		return nil, fmt.Errorf("failed to write integrity hash: %w", err)
	}
	if _, err := mac.Write(h.padding[:]); err != nil {
		return nil, fmt.Errorf("failed to write padding: %w", err)
	}

	return mac.Sum(nil), nil
}

// computeChecksum calculates the CRC32 checksum of the entire header.
// This is a non-cryptographic check to detect accidental data corruption.
func computeChecksum(h *Header) (uint32, error) {
	crc := crc32.NewIEEE()
	if err := writeDataForChecksum(crc, h); err != nil {
		return 0, fmt.Errorf("failed to compute checksum: %w", err)
	}
	return crc.Sum32(), nil
}

// writeStructuralData writes the core metadata fields of the header to an io.Writer.
// This data is used for computing the integrity hash and authentication tag.
func writeStructuralData(w io.Writer, h *Header) error {
	fields := [][]byte{
		h.magic[:],
		utils.ToBytes(h.version),
		utils.ToBytes(h.flags),
		h.salt[:],
		utils.ToBytes(h.originalSize),
	}

	for i, field := range fields {
		if _, err := w.Write(field); err != nil {
			return fmt.Errorf("failed to write field %d: %w", i, err)
		}
	}
	return nil
}

// writeDataForChecksum writes all header fields except the checksum itself to an io.Writer.
// This is used to calculate the header's checksum.
func writeDataForChecksum(w io.Writer, h *Header) error {
	if err := writeStructuralData(w, h); err != nil {
		return err
	}

	if _, err := w.Write(h.integrityHash[:]); err != nil {
		return err
	}
	if _, err := w.Write(h.authTag[:]); err != nil {
		return err
	}
	if _, err := w.Write(h.padding[:]); err != nil {
		return err
	}
	return nil
}

// verifyFormat checks that the header has a valid format.
// This includes checking the magic bytes, version, original size, and required flags.
func verifyFormat(h *Header, _ []byte) error {
	if !hmac.Equal(h.magic[:], []byte(MagicBytes)) {
		return fmt.Errorf("invalid magic bytes")
	}
	if h.version == 0 {
		return fmt.Errorf("invalid version")
	}
	if h.version > CurrentVersion {
		return fmt.Errorf("unsupported version: %d (maximum supported: %d)", h.version, CurrentVersion)
	}
	if h.originalSize == 0 {
		return fmt.Errorf("invalid original size")
	}
	// Ensure that all security flags are set for maximum protection.
	if !h.HasFlag(FlagEncrypted) || !h.HasFlag(FlagIntegrityV2) || !h.HasFlag(FlagAntiTamper) {
		return fmt.Errorf("header created without maximum security, missing required flags")
	}
	return nil
}

// verifyChecksum recalculates the checksum of the header and compares it to the stored checksum.
// This helps detect accidental data corruption.
func verifyChecksum(h *Header, _ []byte) error {
	expected, err := computeChecksum(h)
	if err != nil {
		return fmt.Errorf("failed to compute expected checksum: %w", err)
	}
	if h.checksum != expected {
		return fmt.Errorf("checksum mismatch: expected %08x, got %08x", expected, h.checksum)
	}
	return nil
}

// verifyIntegrity recalculates the integrity hash and compares it to the stored hash.
// This verifies that the header's structural data has not been tampered with.
func verifyIntegrity(h *Header, _ []byte) error {
	expected, err := computeIntegrityHash(h)
	if err != nil {
		return fmt.Errorf("failed to compute expected integrity hash: %w", err)
	}
	if !hmac.Equal(h.integrityHash[:], expected) {
		return fmt.Errorf("integrity hash mismatch")
	}
	return nil
}

// verifyAuth recalculates the authentication tag and compares it to the stored tag.
// This verifies the authenticity of the header using the secret key.
func verifyAuth(h *Header, key []byte) error {
	if len(key) == 0 {
		return fmt.Errorf("key cannot be empty")
	}
	expected, err := computeAuthTag(h, key)
	if err != nil {
		return fmt.Errorf("failed to compute expected auth tag: %w", err)
	}
	if !hmac.Equal(h.authTag[:], expected) {
		return fmt.Errorf("authentication tag mismatch")
	}
	return nil
}

// verifyTampering checks for signs of tampering, such as zeroed-out security fields.
// This provides an extra layer of security against naive attacks.
func verifyTampering(h *Header, _ []byte) error {
	if isAllZeros(h.salt[:]) {
		return fmt.Errorf("possible tampering detected: invalid salt")
	}
	if isAllZeros(h.padding[:]) {
		return fmt.Errorf("possible tampering detected: invalid padding")
	}
	if isAllZeros(h.integrityHash[:]) {
		return fmt.Errorf("possible tampering detected: invalid integrity hash")
	}
	if isAllZeros(h.authTag[:]) {
		return fmt.Errorf("possible tampering detected: invalid auth tag")
	}
	return nil
}

// isAllZeros checks if a byte slice contains only zero bytes.
func isAllZeros(data []byte) bool {
	zeroField := make([]byte, len(data))
	return hmac.Equal(data, zeroField)
}
