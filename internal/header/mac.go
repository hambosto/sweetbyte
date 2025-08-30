// Package header provides functionality for creating, reading, and writing
// authenticated file headers using direct struct serialization.
package header

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

// computeMAC calculates the HMAC-SHA256 of a series of byte slices.
// It takes a secret key and a variable number of byte slices (parts) that
// will be concatenated and authenticated. The function ensures that the key
// is not empty and iteratively writes each part to the HMAC hash.
//
// This function is central to creating the message authentication code (MAC)
// that protects the header's integrity.
//
// Returns the computed MAC as a byte slice or an error if the key is empty
// or if writing to the HMAC fails.
func computeMAC(key []byte, parts ...[]byte) ([]byte, error) {
	// A key is required to compute the HMAC.
	if len(key) == 0 {
		return nil, fmt.Errorf("key cannot be empty")
	}

	// Create a new HMAC instance with SHA256 as the hash function and the provided key.
	mac := hmac.New(sha256.New, key)

	// Iterate over all the parts and write them to the HMAC hash.
	// The order of parts is significant and must be consistent between
	// MAC generation and verification.
	for i, part := range parts {
		if _, err := mac.Write(part); err != nil {
			// If writing fails, return a descriptive error.
			return nil, fmt.Errorf("failed to write part %d to HMAC: %w", i, err)
		}
	}

	// Finalize the HMAC computation and return the resulting MAC.
	return mac.Sum(nil), nil
}

// verifyMAC re-computes the HMAC for a set of parts and compares it with an
// expected MAC in constant time. This constant-time comparison is crucial
// to prevent timing attacks, where an attacker could infer information about
// the expected MAC by measuring the time it takes for the comparison to complete.
//
// It first computes the expected MAC using the same key and parts, then uses
// `hmac.Equal` for a secure comparison.
//
// Returns an error if the MACs do not match or if the computation of the
// expected MAC fails.
func verifyMAC(key, macToVerify []byte, parts ...[]byte) error {
	// Re-compute the MAC using the same key and parts that were originally used.
	expectedMAC, err := computeMAC(key, parts...)
	if err != nil {
		return fmt.Errorf("failed to compute expected MAC: %w", err)
	}

	// Compare the provided MAC with the re-computed MAC in constant time.
	// This is critical for security.
	if !hmac.Equal(macToVerify, expectedMAC) {
		return fmt.Errorf("header MAC verification failed")
	}

	// If the MACs match, verification is successful.
	return nil
}
