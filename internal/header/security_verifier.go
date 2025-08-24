package header

import (
	"fmt"

	"github.com/hambosto/sweetbyte/internal/utils"
)

// TamperVerifier verifies anti-tampering measures
type TamperVerifier struct{}

// NewTamperVerifier creates a new TamperVerifier
func NewTamperVerifier() *TamperVerifier {
	return &TamperVerifier{}
}

// Verify verifies the anti-tampering measures of the header
func (tv *TamperVerifier) Verify(h *Header) error {
	fields := []struct {
		data []byte
		name string
	}{
		{h.salt[:], "salt"},
		{h.padding[:], "padding"},
		{h.integrityHash[:], "integrity hash"},
		{h.authTag[:], "auth tag"},
	}

	for _, field := range fields {
		if tv.isAllZeros(field.data) {
			return fmt.Errorf("invalid %s: all zeros detected - possible tampering", field.name)
		}
	}

	return nil
}

func (tv *TamperVerifier) isAllZeros(data []byte) bool {
	zeroData := make([]byte, len(data))
	return utils.SecureCompare(data, zeroData)
}

// PatternVerifier verifies security patterns
type PatternVerifier struct{}

// NewPatternVerifier creates a new PatternVerifier
func NewPatternVerifier() *PatternVerifier {
	return &PatternVerifier{}
}

// Verify verifies the security patterns of the header
func (pv *PatternVerifier) Verify(h *Header) error {
	fields := []struct {
		data      []byte
		name      string
		minUnique int
	}{
		{h.salt[:], "salt", SaltSize / 4},
		{h.padding[:], "padding", PaddingSize / 4},
	}

	for _, field := range fields {
		if err := pv.checkForRepeatingBytes(field.data, field.name); err != nil {
			return err
		}
		if err := pv.validateEntropy(field.data, field.name, field.minUnique); err != nil {
			return err
		}
	}

	return nil
}

func (pv *PatternVerifier) checkForRepeatingBytes(data []byte, fieldName string) error {
	if len(data) < 4 {
		return nil
	}

	// Check if all bytes are the same
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

	// Check for simple patterns
	if pv.hasSimplePattern(data) {
		return fmt.Errorf("suspicious %s: sequential pattern detected - possible tampering", fieldName)
	}

	return nil
}

func (pv *PatternVerifier) hasSimplePattern(data []byte) bool {
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
