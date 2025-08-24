// Package header provides functionality for creating, reading, and writing file headers.
package header

import (
	"fmt"

	"github.com/hambosto/sweetbyte/internal/utils"
)

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
	// Define the set of flags that are mandatory for security.
	requiredFlags := []struct {
		flag uint32
		name string
	}{
		{FlagEncrypted, "encryption"},
		{FlagIntegrityV2, "integrity v2"},
		{FlagAntiTamper, "anti-tamper"},
	}

	// Iterate through the required flags and check if they are set.
	for _, rf := range requiredFlags {
		if !h.HasFlag(rf.flag) {
			return fmt.Errorf("%s flag not set - header created without maximum security", rf.name)
		}
	}

	return nil
}
