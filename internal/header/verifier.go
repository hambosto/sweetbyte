// Package header provides functionality for creating, reading, and writing file headers.
package header

import (
	"fmt"
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
	patternVerifier := NewPatternVerifier()

	// Define the sequence of verifications to be performed.
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

	// Execute each verifier in order, wrapping any error with the verifier's name.
	for _, verifier := range verifiers {
		if err := verifier.fn(header); err != nil {
			return fmt.Errorf("%s verification failed: %w", verifier.name, err)
		}
	}

	return nil
}
