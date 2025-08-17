// Package header manages the secure header of SweetByte encrypted files.
// It defines the header structure, provides mechanisms for its creation, serialization,
// deserialization, and crucial verification processes to ensure data integrity and authenticity.
package header

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"hash/crc32"
	"io"
)

// Protector is responsible for computing and setting the cryptographic protection
// fields within a Header, including the integrity hash (SHA-256), authentication tag (HMAC-SHA256),
// and checksum (CRC32). These protections ensure the header's integrity and authenticity.
type Protector struct {
	key []byte // The cryptographic key used for HMAC-SHA256 authentication.
}

// NewProtector creates and returns a new Protector instance with the provided key.
// This key is used for computing the HMAC-SHA256 authentication tag.
func NewProtector(key []byte) *Protector {
	return &Protector{
		key: key, // Store the provided key for HMAC computations.
	}
}

// ComputeAllProtection computes and sets the integrity hash, authentication tag, and checksum
// for the given Header. This method orchestrates the various protection computations.
func (p *Protector) ComputeAllProtection(header *Header) error {
	// Compute and set the SHA-256 integrity hash.
	integrityHash, err := p.ComputeIntegrityHash(header)
	if err != nil {
		return fmt.Errorf("integrity hash computation failed: %w", err)
	}
	copy(header.integrityHash[:], integrityHash) // Copy the computed hash into the header.

	// Compute and set the HMAC-SHA256 authentication tag.
	authTag, err := p.ComputeAuthTag(header)
	if err != nil {
		return fmt.Errorf("auth tag computation failed: %w", err)
	}
	copy(header.authTag[:], authTag) // Copy the computed tag into the header.

	// Compute and set the CRC32 checksum.
	checksum, err := p.ComputeChecksum(header)
	if err != nil {
		return fmt.Errorf("checksum computation failed: %w", err)
	}
	header.checksum = checksum // Assign the computed checksum to the header.

	return nil
}

// ComputeIntegrityHash calculates the SHA-256 hash of specific structural fields of the header.
// This hash is used to verify the integrity of the header's metadata.
func (p *Protector) ComputeIntegrityHash(header *Header) ([]byte, error) {
	hasher := sha256.New() // Initialize a new SHA-256 hasher.

	// Write the structural data fields to the hasher.
	if err := p.writeStructuralData(hasher, header); err != nil {
		return nil, fmt.Errorf("failed to write structural data: %w", err)
	}

	return hasher.Sum(nil), nil // Return the computed SHA-256 hash.
}

// ComputeAuthTag calculates the HMAC-SHA256 authentication tag for the header.
// This tag protects the header against tampering and ensures its authenticity.
func (p *Protector) ComputeAuthTag(header *Header) ([]byte, error) {
	if len(p.key) == 0 { // Ensure a key is provided for HMAC computation.
		return nil, fmt.Errorf("key required for authentication tag")
	}

	mac := hmac.New(sha256.New, p.key) // Initialize a new HMAC-SHA256 with the provided key.
	// Write the structural data fields to the HMAC.
	if err := p.writeStructuralData(mac, header); err != nil {
		return nil, fmt.Errorf("failed to write structural data: %w", err)
	}

	// Additionally, write the integrity hash and padding to the HMAC to include them in the authentication.
	if _, err := mac.Write(header.integrityHash[:]); err != nil {
		return nil, fmt.Errorf("failed to write integrity hash: %w", err)
	}

	if _, err := mac.Write(header.padding[:]); err != nil {
		return nil, fmt.Errorf("failed to write padding: %w", err)
	}

	return mac.Sum(nil), nil // Return the computed HMAC-SHA256 tag.
}

// ComputeChecksum calculates the CRC32 checksum of the entire header data.
// This checksum provides a quick and efficient way to detect accidental data corruption.
func (p *Protector) ComputeChecksum(header *Header) (uint32, error) {
	crc := crc32.NewIEEE() // Initialize a new IEEE CRC32 hasher.

	// Write all relevant header data to the CRC32 hasher.
	if err := p.writeDataForChecksum(crc, header); err != nil {
		return 0, fmt.Errorf("failed to compute checksum: %w", err)
	}

	return crc.Sum32(), nil // Return the computed CRC32 checksum.
}

// writeStructuralData writes core header fields to an io.Writer (typically a hash or HMAC function).
// This data forms the basis for integrity and authenticity checks.
func (p *Protector) writeStructuralData(w io.Writer, header *Header) error {
	fields := [][]byte{
		header.magic[:],                    // Magic bytes.
		uint16ToBytes(header.version),      // Version.
		uint32ToBytes(header.flags),        // Flags.
		header.salt[:],                     // Salt.
		uint64ToBytes(header.originalSize), // Original file size.
	}

	for i, field := range fields {
		if _, err := w.Write(field); err != nil {
			return fmt.Errorf("failed to write field %d: %w", i, err)
		}
	}

	return nil
}

// writeDataForChecksum writes all header fields relevant for checksum computation to an io.Writer.
// This includes structural data, integrity hash, authentication tag, and padding.
func (p *Protector) writeDataForChecksum(w io.Writer, header *Header) error {
	if err := p.writeStructuralData(w, header); err != nil {
		return err
	}

	fields := [][]byte{
		header.integrityHash[:], // Integrity hash.
		header.authTag[:],       // Authentication tag.
		header.padding[:],       // Padding.
	}

	for i, field := range fields {
		if _, err := w.Write(field); err != nil {
			return fmt.Errorf("failed to write protection field %d: %w", i, err)
		}
	}

	return nil
}
