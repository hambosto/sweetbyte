// Package header provides functionality for creating, reading, and writing file headers.
package header

import (
	"fmt"

	"github.com/hambosto/sweetbyte/internal/utils"
)

// ValidateForSerialization checks the header fields just before it is written to a stream.
// This ensures that all computed fields (like hashes and tags) are present and valid.
func ValidateForSerialization(h *Header) error {
	// A list of validation functions to be executed in order.
	validators := []func(*Header) error{
		validateMagicBytes,
		validateVersion,
		validateOriginalSize,
		validateSalt,
		validateIntegrityHash,
		validateAuthTag,
	}

	// Execute each validator and return immediately on the first error.
	for _, validator := range validators {
		if err := validator(h); err != nil {
			return err
		}
	}

	return nil
}

// ValidateAfterDeserialization checks the header fields immediately after it has been read from a stream.
// This focuses on the fields that are not dependent on cryptographic verification.
func ValidateAfterDeserialization(h *Header) error {
	// A list of validation functions for the initial check after reading.
	validators := []func(*Header) error{
		validateMagicBytes,
		validateVersion,
		validateOriginalSize,
		validateSalt,
	}

	// Execute each validator and return on the first error.
	for _, validator := range validators {
		if err := validator(h); err != nil {
			return err
		}
	}

	return nil
}

// validateMagicBytes ensures that the magic bytes of the header are correct.
func validateMagicBytes(h *Header) error {
	if !utils.SecureCompare(h.magic[:], []byte(MagicBytes)) {
		return fmt.Errorf("invalid magic bytes: expected %s, got %s", MagicBytes, string(h.magic[:]))
	}
	return nil
}

// validateVersion checks that the header version is supported.
func validateVersion(h *Header) error {
	if h.version == 0 {
		return fmt.Errorf("invalid version: cannot be zero")
	}
	if h.version > CurrentVersion {
		return fmt.Errorf("unsupported version: %d (maximum supported: %d)", h.version, CurrentVersion)
	}
	return nil
}

// validateOriginalSize ensures that the original size is a non-zero value.
func validateOriginalSize(h *Header) error {
	if h.originalSize == 0 {
		return fmt.Errorf("invalid original size: cannot be zero")
	}
	return nil
}

// validateSalt checks that the salt field is not all zeros.
func validateSalt(h *Header) error {
	return validateNonZeroField(h.salt[:], "salt")
}

// validateIntegrityHash checks that the integrity hash field is not all zeros.
func validateIntegrityHash(h *Header) error {
	return validateNonZeroField(h.integrityHash[:], "integrity hash")
}

// validateAuthTag checks that the authentication tag field is not all zeros.
func validateAuthTag(h *Header) error {
	return validateNonZeroField(h.authTag[:], "auth tag")
}

// validateNonZeroField is a generic helper to check if a byte slice is all zeros.
func validateNonZeroField(field []byte, fieldName string) error {
	zeroField := make([]byte, len(field))
	if utils.SecureCompare(field, zeroField) {
		return fmt.Errorf("%s cannot be all zeros", fieldName)
	}
	return nil
}
