package header

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
)

type MACProcessor struct{}

func NewMACProcessor() *MACProcessor {
	return &MACProcessor{}
}

func (mp *MACProcessor) ComputeMAC(key []byte, parts ...[]byte) ([]byte, error) {
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

func (mp *MACProcessor) VerifyMAC(key, expectedMAC []byte, parts ...[]byte) error {
	computedMAC, err := mp.ComputeMAC(key, parts...)
	if err != nil {
		return fmt.Errorf("failed to compute MAC: %w", err)
	}
	if !hmac.Equal(expectedMAC, computedMAC) {
		return fmt.Errorf("MAC verification failed")
	}
	return nil
}

// Package-level convenience functions for backward compatibility
func ComputeMAC(key []byte, parts ...[]byte) ([]byte, error) {
	mp := NewMACProcessor()
	return mp.ComputeMAC(key, parts...)
}

func VerifyMAC(key, expectedMAC []byte, parts ...[]byte) error {
	mp := NewMACProcessor()
	return mp.VerifyMAC(key, expectedMAC, parts...)
}
