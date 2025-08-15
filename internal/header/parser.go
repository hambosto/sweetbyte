package header

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"hash/crc32"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/errors"
)

// Parser handles the parsing logic for binary header data
type Parser struct {
	data   []byte
	offset int
}

// NewParser creates a new binary data parser
func NewParser(data []byte) *Parser {
	return &Parser{
		data:   data,
		offset: 0,
	}
}

// Parse parses the header data
func (p *Parser) Parse() (*Header, error) {
	if err := p.verifyMagic(); err != nil {
		return nil, err
	}

	header := &Header{
		metadata:   &Metadata{},
		protection: &Protection{},
	}

	if err := p.parseMetadata(header.metadata); err != nil {
		return nil, err
	}

	if err := p.parseProtection(header.protection); err != nil {
		return nil, err
	}

	if err := p.verifyChecksum(); err != nil {
		return nil, err
	}

	if err := p.verifyStructuralIntegrity(header); err != nil {
		return nil, err
	}

	return header, nil
}

// verifyMagic checks the magic bytes
func (p *Parser) verifyMagic() error {
	magicBytes := []byte(config.MagicBytes)
	if subtle.ConstantTimeCompare(p.data[:len(magicBytes)], magicBytes) != 1 {
		return errors.ErrInvalidMagic
	}
	p.offset = len(magicBytes)
	return nil
}

// parseMetadata extracts metadata fields
func (p *Parser) parseMetadata(m *Metadata) error {
	m.salt = CloneBytes(p.readBytes(config.SaltSizeBytes))
	m.originalSize = p.readUint64()
	return nil
}

// parseProtection extracts protection fields
func (p *Parser) parseProtection(prot *Protection) error {
	prot.integrityHash = CloneBytes(p.readBytes(config.IntegritySize))
	prot.authTag = CloneBytes(p.readBytes(config.AuthSize))
	return nil
}

// verifyChecksum validates the CRC32 checksum
func (p *Parser) verifyChecksum() error {
	checksumStart := len([]byte(config.MagicBytes))
	checksumEnd := p.offset
	checksumData := p.data[checksumStart:checksumEnd]

	expected := Uint32ToBytes(crc32.ChecksumIEEE(checksumData))
	actual := p.readBytes(config.ChecksumSize)

	if subtle.ConstantTimeCompare(actual, expected) != 1 {
		return errors.ErrChecksumMismatch
	}
	return nil
}

// verifyStructuralIntegrity checks the integrity hash
func (p *Parser) verifyStructuralIntegrity(h *Header) error {
	verifier := NewVerifier(h, nil)
	expected := verifier.computeIntegrityHash()
	if !bytes.Equal(h.protection.integrityHash, expected) {
		return errors.ErrTampering
	}
	return nil
}

// readBytes reads n bytes from the current offset
func (p *Parser) readBytes(n int) []byte {
	result := p.data[p.offset : p.offset+n]
	p.offset += n
	return result
}

// readUint64 reads a uint64 from the current offset
func (p *Parser) readUint64() uint64 {
	result := binary.BigEndian.Uint64(p.data[p.offset : p.offset+8])
	p.offset += 8
	return result
}
