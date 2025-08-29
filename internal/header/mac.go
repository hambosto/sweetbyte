package header

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

// computeMAC calculates the HMAC-SHA256 of a series of byte slices.
// It concatenates the `parts` and computes the MAC using the provided `key`.
// This function is central to providing authenticated integrity protection for the header data,
// ensuring that it has not been tampered with.
func computeMAC(key []byte, parts ...[]byte) ([]byte, error) {
	// A key is required to compute the HMAC.
	if len(key) == 0 {
		return nil, fmt.Errorf("key cannot be empty")
	}

	// Create a new HMAC instance with SHA256 as the hash function.
	mac := hmac.New(sha256.New, key)
	// Write each part to the HMAC instance. The order of parts is critical.
	for i, part := range parts {
		if _, err := mac.Write(part); err != nil {
			// This error is unlikely but handled for robustness.
			return nil, fmt.Errorf("failed to write part %d to HMAC: %w", i, err)
		}
	}

	// Finalize the HMAC computation and return the result.
	return mac.Sum(nil), nil
}

// verifyMAC re-computes the HMAC for a set of parts and compares it with a provided
// MAC in constant time. This is used to verify the integrity and authenticity of the header.
// Constant-time comparison is crucial to prevent timing attacks.
func verifyMAC(key, macToVerify []byte, parts ...[]byte) error {
	// Re-compute the HMAC using the same key and parts.
	expectedMAC, err := computeMAC(key, parts...)
	if err != nil {
		return fmt.Errorf("failed to compute expected MAC: %w", err)
	}

	// Compare the provided MAC with the expected MAC using a constant-time comparison.
	// hmac.Equal prevents timing side-channel attacks, where an attacker could
	// infer information about the MAC by measuring the time it takes for the comparison to complete.
	if !hmac.Equal(macToVerify, expectedMAC) {
		return fmt.Errorf("header MAC verification failed")
	}

	// If the MACs match, the header is considered authentic.
	return nil
}