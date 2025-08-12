package header

import (
	"fmt"
	"hash/crc32"
	"io"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/errors"
)

// Serializer handles header serialization
type Serializer struct {
	header *Header
}

// NewSerializer creates a new header serializer
func NewSerializer(header *Header) *Serializer {
	return &Serializer{header: header}
}

// WriteTo writes the serialized header to the writer
func (s *Serializer) WriteTo(w io.Writer) (int64, error) {
	if err := s.validate(); err != nil {
		return 0, err
	}

	data := s.marshal()
	n, err := w.Write(data)
	if err != nil {
		return int64(n), fmt.Errorf("failed to write header: %w", err)
	}

	if n != len(data) {
		return int64(n), fmt.Errorf("%w: wrote %d of %d bytes", errors.ErrIncompleteWrite, n, len(data))
	}

	return int64(n), nil
}

// validate checks if the header is ready for serialization
func (s *Serializer) validate() error {
	h := s.header
	validators := []struct {
		condition bool
		err       error
		got       int
		expected  int
	}{
		{
			len(h.metadata.salt) != config.SaltSizeBytes, errors.ErrInvalidSalt,
			len(h.metadata.salt), config.SaltSizeBytes,
		},
		{
			len(h.metadata.nonce) != config.NonceSizeBytes, errors.ErrInvalidNonce,
			len(h.metadata.nonce), config.NonceSizeBytes,
		},
		{
			len(h.protection.integrityHash) != config.IntegritySize, errors.ErrInvalidIntegrity,
			len(h.protection.integrityHash), config.IntegritySize,
		},
		{
			len(h.protection.authTag) != config.AuthSize, errors.ErrInvalidAuth,
			len(h.protection.authTag), config.AuthSize,
		},
	}

	for _, v := range validators {
		if v.condition {
			return fmt.Errorf("%w: expected %d bytes, got %d", v.err, v.expected, v.got)
		}
	}
	return nil
}

// marshal serializes the header to bytes
func (s *Serializer) marshal() []byte {
	h := s.header
	var buf []byte

	// Write header fields in order
	buf = append(buf, []byte(config.MagicBytes)...)
	buf = append(buf, h.metadata.salt...)
	buf = append(buf, Uint64ToBytes(h.metadata.originalSize)...)
	buf = append(buf, h.metadata.nonce...)
	buf = append(buf, h.protection.integrityHash...)
	buf = append(buf, h.protection.authTag...)

	// Calculate and append checksum (excluding magic bytes)
	checksumData := buf[len(config.MagicBytes):]
	checksum := crc32.ChecksumIEEE(checksumData)
	buf = append(buf, Uint32ToBytes(checksum)...)

	return buf
}
