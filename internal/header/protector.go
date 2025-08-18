// Package header provides functionality for creating, reading, and writing file headers.
package header

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"hash/crc32"
	"io"
)

// Protector computes the protection fields of a header.
type Protector struct {
	key []byte
}

// NewProtector creates a new Protector.
func NewProtector(key []byte) *Protector {
	return &Protector{
		key: key,
	}
}

// ComputeAllProtection computes all protection fields for the header.
func (p *Protector) ComputeAllProtection(header *Header) error {
	// Compute the integrity hash.
	integrityHash, err := p.ComputeIntegrityHash(header)
	if err != nil {
		return fmt.Errorf("integrity hash computation failed: %w", err)
	}
	copy(header.integrityHash[:], integrityHash)

	// Compute the authentication tag.
	authTag, err := p.ComputeAuthTag(header)
	if err != nil {
		return fmt.Errorf("auth tag computation failed: %w", err)
	}
	copy(header.authTag[:], authTag)

	// Compute the checksum.
	checksum, err := p.ComputeChecksum(header)
	if err != nil {
		return fmt.Errorf("checksum computation failed: %w", err)
	}
	header.checksum = checksum

	return nil
}

// ComputeIntegrityHash computes the integrity hash of the header.
func (p *Protector) ComputeIntegrityHash(header *Header) ([]byte, error) {
	hasher := sha256.New()
	if err := p.writeStructuralData(hasher, header); err != nil {
		return nil, fmt.Errorf("failed to write structural data: %w", err)
	}

	return hasher.Sum(nil), nil
}

// ComputeAuthTag computes the authentication tag of the header.
func (p *Protector) ComputeAuthTag(header *Header) ([]byte, error) {
	if len(p.key) == 0 {
		return nil, fmt.Errorf("key required for authentication tag")
	}

	// Create a new HMAC with SHA256.
	mac := hmac.New(sha256.New, p.key)
	// Write the structural data to the HMAC.
	if err := p.writeStructuralData(mac, header); err != nil {
		return nil, fmt.Errorf("failed to write structural data: %w", err)
	}

	// Write the integrity hash to the HMAC.
	if _, err := mac.Write(header.integrityHash[:]); err != nil {
		return nil, fmt.Errorf("failed to write integrity hash: %w", err)
	}

	// Write the padding to the HMAC.
	if _, err := mac.Write(header.padding[:]); err != nil {
		return nil, fmt.Errorf("failed to write padding: %w", err)
	}

	return mac.Sum(nil), nil
}

// ComputeChecksum computes the checksum of the header.
func (p *Protector) ComputeChecksum(header *Header) (uint32, error) {
	crc := crc32.NewIEEE()
	if err := p.writeDataForChecksum(crc, header); err != nil {
		return 0, fmt.Errorf("failed to compute checksum: %w", err)
	}

	return crc.Sum32(), nil
}

// writeStructuralData writes the structural data of the header to an io.Writer.
func (p *Protector) writeStructuralData(w io.Writer, header *Header) error {
	fields := [][]byte{
		header.magic[:],
		uint16ToBytes(header.version),
		uint32ToBytes(header.flags),
		header.salt[:],
		uint64ToBytes(header.originalSize),
	}

	for i, field := range fields {
		if _, err := w.Write(field); err != nil {
			return fmt.Errorf("failed to write field %d: %w", i, err)
		}
	}

	return nil
}

// writeDataForChecksum writes the data for checksum computation to an io.Writer.
func (p *Protector) writeDataForChecksum(w io.Writer, header *Header) error {
	if err := p.writeStructuralData(w, header); err != nil {
		return err
	}

	fields := [][]byte{
		header.integrityHash[:],
		header.authTag[:],
		header.padding[:],
	}

	for i, field := range fields {
		if _, err := w.Write(field); err != nil {
			return fmt.Errorf("failed to write protection field %d: %w", i, err)
		}
	}

	return nil
}
