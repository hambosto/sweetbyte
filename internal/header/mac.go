package header

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

// computeMAC calculates HMAC-SHA256 over a series of byte slices.
// This provides authenticated integrity protection for the header data.
func computeMAC(key []byte, parts ...[]byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("key cannot be empty")
	}

	mac := hmac.New(sha256.New, key)
	for i, part := range parts {
		if _, err := mac.Write(part); err != nil {
			return nil, fmt.Errorf("failed to write part %d to HMAC: %w", i, err)
		}
	}

	return mac.Sum(nil), nil
}

// verifyMAC computes the expected HMAC and compares it with the provided MAC using constant-time comparison.
func verifyMAC(key, macToVerify []byte, parts ...[]byte) error {
	expectedMAC, err := computeMAC(key, parts...)
	if err != nil {
		return fmt.Errorf("failed to compute expected MAC: %w", err)
	}

	if !hmac.Equal(macToVerify, expectedMAC) {
		return fmt.Errorf("header MAC verification failed")
	}

	return nil
}
