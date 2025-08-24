// Package header provides functionality for creating, reading, and writing file headers.
package header

import (
	"fmt"

	"github.com/hambosto/sweetbyte/internal/utils"
)

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
	// Define the fields to be checked for all-zero content.
	fields := []struct {
		data []byte
		name string
	}{
		{h.salt[:], "salt"},
		{h.padding[:], "padding"},
		{h.integrityHash[:], "integrity hash"},
		{h.authTag[:], "auth tag"},
	}

	// Iterate through the fields and check each one.
	for _, field := range fields {
		if tv.isAllZeros(field.data) {
			return fmt.Errorf("invalid %s: all zeros detected - possible tampering", field.name)
		}
	}

	return nil
}

// isAllZeros performs a secure comparison of a byte slice against an all-zero slice of the same length.
func (tv *TamperVerifier) isAllZeros(data []byte) bool {
	zeroData := make([]byte, len(data))
	return utils.SecureCompare(data, zeroData)
}

// PatternVerifier checks for non-random patterns in security-sensitive fields.
// This helps detect weak or predictable generation of fields like salt and padding.
type PatternVerifier struct{}

// NewPatternVerifier creates a new PatternVerifier instance.
func NewPatternVerifier() *PatternVerifier {
	return &PatternVerifier{}
}

// Verify runs a series of checks on the header's random data fields (salt, padding)
// to ensure they have sufficient entropy and do not contain suspicious patterns.
func (pv *PatternVerifier) Verify(h *Header) error {
	// Define the fields to be checked for entropy and patterns.
	fields := []struct {
		data      []byte
		name      string
		minUnique int
	}{
		{h.salt[:], "salt", SaltSize / 4},          // Require at least 1/4 unique bytes for salt.
		{h.padding[:], "padding", PaddingSize / 4}, // Require at least 1/4 unique bytes for padding.
	}

	for _, field := range fields {
		// Check for repeating byte patterns.
		if err := pv.checkForRepeatingBytes(field.data, field.name); err != nil {
			return err
		}
		// Validate the entropy by checking the number of unique bytes.
		if err := pv.validateEntropy(field.data, field.name, field.minUnique); err != nil {
			return err
		}
	}

	return nil
}

// checkForRepeatingBytes detects simple, non-random patterns like all identical bytes or sequential bytes.
func (pv *PatternVerifier) checkForRepeatingBytes(data []byte, fieldName string) error {
	if len(data) < 4 {
		return nil // Not enough data to detect a meaningful pattern.
	}

	// Check if all bytes in the slice are identical.
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

	// Check for simple sequential patterns (e.g., 1, 2, 3, 4...).
	if pv.hasSimplePattern(data) {
		return fmt.Errorf("suspicious %s: sequential pattern detected - possible tampering", fieldName)
	}

	return nil
}

// hasSimplePattern checks for simple ascending or descending byte sequences.
func (pv *PatternVerifier) hasSimplePattern(data []byte) bool {
	if len(data) < 4 {
		return false
	}

	// Check for an ascending pattern (e.g., 1, 2, 3, ...).
	ascending := true
	for i := 1; i < len(data) && i < 8; i++ { // Limit check to first 8 bytes for performance.
		if data[i] != data[i-1]+1 {
			ascending = false
			break
		}
	}

	// Check for a descending pattern (e.g., 9, 8, 7, ...).
	descending := true
	for i := 1; i < len(data) && i < 8; i++ { // Limit check to first 8 bytes.
		if data[i] != data[i-1]-1 {
			descending = false
			break
		}
	}

	return ascending || descending
}

// validateEntropy checks if a byte slice has a minimum number of unique bytes.
// This is a simple heuristic to ensure a degree of randomness.
func (pv *PatternVerifier) validateEntropy(data []byte, fieldName string, minUnique int) error {
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
