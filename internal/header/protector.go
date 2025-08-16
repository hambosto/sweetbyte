package header

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"hash/crc32"
	"io"
)

// Protector handles all protection mechanisms
type Protector struct {
	key []byte
}

// NewProtector creates a new protector instance
func NewProtector(key []byte) *Protector {
	return &Protector{
		key: key,
	}
}

// ComputeAllProtection calculates all protection mechanisms in proper order
func (p *Protector) ComputeAllProtection(header *Header) error {
	// Step 1: Compute integrity hash (covers structural data)
	integrityHash, err := p.ComputeIntegrityHash(header)
	if err != nil {
		return fmt.Errorf("integrity hash computation failed: %w", err)
	}
	copy(header.integrityHash[:], integrityHash)

	// Step 2: Compute authentication tag (covers integrity hash + key)
	authTag, err := p.ComputeAuthTag(header)
	if err != nil {
		return fmt.Errorf("auth tag computation failed: %w", err)
	}
	copy(header.authTag[:], authTag)

	// Step 3: Compute checksum (covers everything except checksum itself)
	checksum, err := p.ComputeChecksum(header)
	if err != nil {
		return fmt.Errorf("checksum computation failed: %w", err)
	}
	header.checksum = checksum

	return nil
}

// ComputeIntegrityHash calculates SHA-256 hash of structural data
func (p *Protector) ComputeIntegrityHash(header *Header) ([]byte, error) {
	hasher := sha256.New()

	if err := p.writeStructuralData(hasher, header); err != nil {
		return nil, fmt.Errorf("failed to write structural data: %w", err)
	}

	return hasher.Sum(nil), nil
}

// ComputeAuthTag calculates HMAC-SHA256 authentication tag
func (p *Protector) ComputeAuthTag(header *Header) ([]byte, error) {
	if len(p.key) == 0 {
		return nil, fmt.Errorf("key required for authentication tag")
	}

	mac := hmac.New(sha256.New, p.key)

	// Include structural data
	if err := p.writeStructuralData(mac, header); err != nil {
		return nil, fmt.Errorf("failed to write structural data: %w", err)
	}

	// Include integrity hash for layered protection
	if _, err := mac.Write(header.integrityHash[:]); err != nil {
		return nil, fmt.Errorf("failed to write integrity hash: %w", err)
	}

	// Include padding for additional entropy
	if _, err := mac.Write(header.padding[:]); err != nil {
		return nil, fmt.Errorf("failed to write padding: %w", err)
	}

	return mac.Sum(nil), nil
}

// ComputeChecksum calculates CRC32 checksum for quick corruption detection
func (p *Protector) ComputeChecksum(header *Header) (uint32, error) {
	crc := crc32.NewIEEE()

	if err := p.writeDataForChecksum(crc, header); err != nil {
		return 0, fmt.Errorf("failed to compute checksum: %w", err)
	}

	return crc.Sum32(), nil
}

// writeStructuralData writes core header fields for hashing
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

// writeDataForChecksum writes all data except checksum itself
func (p *Protector) writeDataForChecksum(w io.Writer, header *Header) error {
	// Write structural data
	if err := p.writeStructuralData(w, header); err != nil {
		return err
	}

	// Write protection fields (except checksum)
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
