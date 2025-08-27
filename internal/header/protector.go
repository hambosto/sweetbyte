// Package header provides functionality for creating, reading, and writing file headers.
package header

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/utils"
)

// Protector is responsible for computing the authentication tag for a header.
type Protector struct {
	key []byte
}

// NewProtector creates a new Protector instance with the given key.
func NewProtector(key []byte) *Protector {
	return &Protector{key: key}
}

// Protect computes the authentication tag and sets it on the header.
func (p *Protector) Protect(header *Header) error {
	if len(p.key) == 0 {
		return fmt.Errorf("key is required to protect the header")
	}

	tag, err := p.ComputeAuthTag(header)
	if err != nil {
		return fmt.Errorf("failed to compute auth tag: %w", err)
	}
	copy(header.authTag[:], tag)
	return nil
}

// ComputeAuthTag calculates the HMAC-SHA256 authentication tag for the header.
func (p *Protector) ComputeAuthTag(header *Header) ([]byte, error) {
	mac := hmac.New(sha256.New, p.key)
	if err := writeAuthenticatedData(mac, header); err != nil {
		return nil, fmt.Errorf("failed to write authenticated data to mac: %w", err)
	}
	return mac.Sum(nil), nil
}

// writeAuthenticatedData writes the header fields that are protected by the auth tag to an io.Writer.
func writeAuthenticatedData(w io.Writer, header *Header) error {
	fields := [][]byte{
		header.magic[:],
		utils.ToBytes(header.version),
		utils.ToBytes(header.flags),
		header.salt[:],
		utils.ToBytes(header.originalSize),
		header.padding[:],
	}

	for i, field := range fields {
		if _, err := w.Write(field); err != nil {
			return fmt.Errorf("failed to write field %d: %w", i, err)
		}
	}
	return nil
}
