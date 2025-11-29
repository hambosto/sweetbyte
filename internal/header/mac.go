package header

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

func ComputeMAC(key []byte, parts ...[]byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("key cannot be empty")
	}

	mac := hmac.New(sha256.New, key)
	for i, part := range parts {
		if len(part) == 0 {
			continue
		}
		if _, err := mac.Write(part); err != nil {
			return nil, fmt.Errorf("failed to write part %d to HMAC: %w", i, err)
		}
	}

	return mac.Sum(nil), nil
}

func VerifyMAC(key, expectedMAC []byte, parts ...[]byte) error {
	computedMAC, err := ComputeMAC(key, parts...)
	if err != nil {
		return fmt.Errorf("failed to compute MAC: %w", err)
	}

	if !hmac.Equal(expectedMAC, computedMAC) {
		return fmt.Errorf("MAC verification failed")
	}
	return nil
}
