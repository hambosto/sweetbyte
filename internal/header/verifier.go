package header

import (
	"fmt"
)

// Verifier coordinates all header verification operations
type Verifier struct {
	key []byte
}

// NewVerifier creates a new Verifier
func NewVerifier(key []byte) *Verifier {
	return &Verifier{key: key}
}

// VerifyAll performs all verification checks on the header
func (v *Verifier) VerifyAll(header *Header) error {
	// Create individual verifiers
	formatVerifier := NewFormatVerifier()
	checksumVerifier := NewChecksumVerifier(v.key)
	integrityVerifier := NewIntegrityVerifier(v.key)
	authVerifier := NewAuthVerifier(v.key)
	tamperVerifier := NewTamperVerifier()
	patternVerifier := NewPatternVerifier()

	// Run all verifications
	verifiers := []struct {
		name string
		fn   func(*Header) error
	}{
		{"format", formatVerifier.Verify},
		{"checksum", checksumVerifier.Verify},
		{"integrity", integrityVerifier.Verify},
		{"authentication", authVerifier.Verify},
		{"anti-tampering", tamperVerifier.Verify},
		{"security patterns", patternVerifier.Verify},
	}

	for _, verifier := range verifiers {
		if err := verifier.fn(header); err != nil {
			return fmt.Errorf("%s verification failed: %w", verifier.name, err)
		}
	}

	return nil
}
