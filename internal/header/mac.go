// Package header provides functionalities for handling file headers.
package header

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

// computeMAC computes the HMAC-SHA256 of the given parts using the given key.
func computeMAC(key []byte, parts ...[]byte) ([]byte, error) {
	// Ensure the key is not empty.
	if len(key) == 0 {
		return nil, fmt.Errorf("key cannot be empty")
	}

	// Create a new HMAC-SHA256 hasher.
	mac := hmac.New(sha256.New, key)
	// Write the parts to the hasher.
	for i, part := range parts {
		if _, err := mac.Write(part); err != nil {
			return nil, fmt.Errorf("failed to write part %d to HMAC: %w", i, err)
		}
	}

	// Return the computed MAC.
	return mac.Sum(nil), nil
}

// verifyMAC verifies the HMAC-SHA256 of the given parts using the given key.
func verifyMAC(key, macToVerify []byte, parts ...[]byte) error {
	// Compute the expected MAC.
	expectedMAC, err := computeMAC(key, parts...)
	if err != nil {
		return fmt.Errorf("failed to compute expected MAC: %w", err)
	}

	// Compare the expected MAC with the given MAC.
	if !hmac.Equal(macToVerify, expectedMAC) {
		return fmt.Errorf("header MAC verification failed")
	}

	return nil
}
