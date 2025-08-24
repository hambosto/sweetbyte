// Package header provides functionality for creating, reading, and writing file headers.
package header

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"hash/crc32"
	"io"

	"github.com/hambosto/sweetbyte/internal/utils"
)

// Protector is responsible for computing the cryptographic and checksum fields of a header.
// This includes the integrity hash, authentication tag, and checksum, which protect
// the header against tampering and corruption.
type Protector struct {
	key []byte // The secret key used for generating the authentication tag.
}

// NewProtector creates a new Protector instance with the given key.
func NewProtector(key []byte) *Protector {
	return &Protector{key: key}
}

// ComputeAllProtection orchestrates the computation of all protection fields for the header.
// It calls the individual computation methods for integrity hash, auth tag, and checksum.
func (p *Protector) ComputeAllProtection(header *Header) error {
	// Compute and set the integrity hash.
	if err := p.computeIntegrityHash(header); err != nil {
		return fmt.Errorf("integrity hash computation failed: %w", err)
	}
	// Compute and set the authentication tag.
	if err := p.computeAuthTag(header); err != nil {
		return fmt.Errorf("auth tag computation failed: %w", err)
	}
	// Compute and set the checksum.
	if err := p.computeChecksum(header); err != nil {
		return fmt.Errorf("checksum computation failed: %w", err)
	}
	return nil
}

// ComputeIntegrityHash calculates and returns the SHA-256 hash of the header's structural data.
// This hash protects against unintentional corruption of the main header fields.
func (p *Protector) ComputeIntegrityHash(header *Header) ([]byte, error) {
	hasher := sha256.New()
	if err := p.writeStructuralData(hasher, header); err != nil {
		return nil, fmt.Errorf("failed to write structural data: %w", err)
	}
	return hasher.Sum(nil), nil
}

// ComputeAuthTag calculates and returns the HMAC-SHA256 authentication tag.
// This tag provides authenticity and integrity for the header, verifiable with a secret key.
func (p *Protector) ComputeAuthTag(header *Header) ([]byte, error) {
	// An authentication key is required.
	if len(p.key) == 0 {
		return nil, fmt.Errorf("key required for authentication tag")
	}

	// Create a new HMAC with SHA-256.
	mac := hmac.New(sha256.New, p.key)
	// Write the core structural data to the HMAC.
	if err := p.writeStructuralData(mac, header); err != nil {
		return nil, fmt.Errorf("failed to write structural data: %w", err)
	}

	// Include the integrity hash in the HMAC computation.
	if _, err := mac.Write(header.integrityHash[:]); err != nil {
		return nil, fmt.Errorf("failed to write integrity hash: %w", err)
	}

	// Include the padding in the HMAC computation.
	if _, err := mac.Write(header.padding[:]); err != nil {
		return nil, fmt.Errorf("failed to write padding: %w", err)
	}

	return mac.Sum(nil), nil
}

// ComputeChecksum calculates and returns the CRC32 checksum of the entire header.
// This provides a fast, non-cryptographic way to detect accidental data corruption.
func (p *Protector) ComputeChecksum(header *Header) (uint32, error) {
	crc := crc32.NewIEEE()
	if err := p.writeDataForChecksum(crc, header); err != nil {
		return 0, fmt.Errorf("failed to compute checksum: %w", err)
	}
	return crc.Sum32(), nil
}

// computeIntegrityHash is an internal helper that computes the integrity hash and sets it on the header.
func (p *Protector) computeIntegrityHash(header *Header) error {
	hash, err := p.ComputeIntegrityHash(header)
	if err != nil {
		return err
	}
	copy(header.integrityHash[:], hash)
	return nil
}

// computeAuthTag is an internal helper that computes the auth tag and sets it on the header.
func (p *Protector) computeAuthTag(header *Header) error {
	tag, err := p.ComputeAuthTag(header)
	if err != nil {
		return err
	}
	copy(header.authTag[:], tag)
	return nil
}

// computeChecksum is an internal helper that computes the checksum and sets it on the header.
func (p *Protector) computeChecksum(header *Header) error {
	checksum, err := p.ComputeChecksum(header)
	if err != nil {
		return err
	}
	header.checksum = checksum
	return nil
}

// writeStructuralData writes the core, non-protection fields of the header to an io.Writer.
// This data is used for both the integrity hash and the authentication tag.
func (p *Protector) writeStructuralData(w io.Writer, header *Header) error {
	fields := [][]byte{
		header.magic[:],
		utils.ToBytes(header.version),
		utils.ToBytes(header.flags),
		header.salt[:],
		utils.ToBytes(header.originalSize),
	}

	for i, field := range fields {
		if _, err := w.Write(field); err != nil {
			return fmt.Errorf("failed to write field %d: %w", i, err)
		}
	}
	return nil
}

// writeDataForChecksum writes all header data, including protection fields, to an io.Writer.
// This is used for calculating the final checksum of the entire header.
func (p *Protector) writeDataForChecksum(w io.Writer, header *Header) error {
	// First, write the structural data.
	if err := p.writeStructuralData(w, header); err != nil {
		return err
	}

	// Then, write the protection fields.
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
