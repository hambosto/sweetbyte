// Package header provides functionality for handling file headers,
// including serialization and deserialization of metadata.
package header

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

// ComputeMAC calculates the HMAC-SHA256 for a series of byte slices (parts).
// It uses the provided key to generate the message authentication code.
// The parts are concatenated and then processed by the HMAC function.
func ComputeMAC(key []byte, parts ...[]byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("key cannot be empty")
	}
	// Create a new HMAC-SHA256 hasher.
	mac := hmac.New(sha256.New, key)
	// Write each part to the hasher.
	for i, part := range parts {
		if len(part) == 0 {
			continue // Skip empty parts.
		}
		if _, err := mac.Write(part); err != nil {
			return nil, fmt.Errorf("failed to write part %d to HMAC: %w", i, err)
		}
	}
	// Return the resulting MAC.
	return mac.Sum(nil), nil
}

// VerifyMAC compares a given MAC with a computed MAC for a series of parts.
// It returns an error if the MACs do not match or if the computation fails.
func VerifyMAC(key, expectedMAC []byte, parts ...[]byte) error {
	// Compute the MAC for the given parts.
	computedMAC, err := ComputeMAC(key, parts...)
	if err != nil {
		return fmt.Errorf("failed to compute MAC: %w", err)
	}
	// Compare the computed MAC with the expected MAC in a constant-time manner.
	if !hmac.Equal(expectedMAC, computedMAC) {
		return fmt.Errorf("MAC verification failed")
	}
	return nil
}
