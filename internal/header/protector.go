package header

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"hash/crc32"
	"io"

	"github.com/hambosto/sweetbyte/internal/utils"
)

// Protector computes protection fields for headers
type Protector struct {
	key []byte
}

// NewProtector creates a new Protector
func NewProtector(key []byte) *Protector {
	return &Protector{key: key}
}

// ComputeAllProtection computes all protection fields for the header
func (p *Protector) ComputeAllProtection(header *Header) error {
	if err := p.computeIntegrityHash(header); err != nil {
		return fmt.Errorf("integrity hash computation failed: %w", err)
	}
	if err := p.computeAuthTag(header); err != nil {
		return fmt.Errorf("auth tag computation failed: %w", err)
	}
	if err := p.computeChecksum(header); err != nil {
		return fmt.Errorf("checksum computation failed: %w", err)
	}
	return nil
}

// ComputeIntegrityHash computes and returns the integrity hash
func (p *Protector) ComputeIntegrityHash(header *Header) ([]byte, error) {
	hasher := sha256.New()
	if err := p.writeStructuralData(hasher, header); err != nil {
		return nil, fmt.Errorf("failed to write structural data: %w", err)
	}
	return hasher.Sum(nil), nil
}

// ComputeAuthTag computes and returns the authentication tag
func (p *Protector) ComputeAuthTag(header *Header) ([]byte, error) {
	if len(p.key) == 0 {
		return nil, fmt.Errorf("key required for authentication tag")
	}

	mac := hmac.New(sha256.New, p.key)
	if err := p.writeStructuralData(mac, header); err != nil {
		return nil, fmt.Errorf("failed to write structural data: %w", err)
	}

	if _, err := mac.Write(header.integrityHash[:]); err != nil {
		return nil, fmt.Errorf("failed to write integrity hash: %w", err)
	}

	if _, err := mac.Write(header.padding[:]); err != nil {
		return nil, fmt.Errorf("failed to write padding: %w", err)
	}

	return mac.Sum(nil), nil
}

// ComputeChecksum computes and returns the checksum
func (p *Protector) ComputeChecksum(header *Header) (uint32, error) {
	crc := crc32.NewIEEE()
	if err := p.writeDataForChecksum(crc, header); err != nil {
		return 0, fmt.Errorf("failed to compute checksum: %w", err)
	}
	return crc.Sum32(), nil
}

func (p *Protector) computeIntegrityHash(header *Header) error {
	hash, err := p.ComputeIntegrityHash(header)
	if err != nil {
		return err
	}
	copy(header.integrityHash[:], hash)
	return nil
}

func (p *Protector) computeAuthTag(header *Header) error {
	tag, err := p.ComputeAuthTag(header)
	if err != nil {
		return err
	}
	copy(header.authTag[:], tag)
	return nil
}

func (p *Protector) computeChecksum(header *Header) error {
	checksum, err := p.ComputeChecksum(header)
	if err != nil {
		return err
	}
	header.checksum = checksum
	return nil
}

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
