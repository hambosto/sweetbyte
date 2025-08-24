package header

import (
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/utils"
)

// Serializer handles serializing headers to byte streams
type Serializer struct {
	validator *Validator
}

// NewSerializer creates a new Serializer
func NewSerializer() *Serializer {
	return &Serializer{
		validator: NewValidator(),
	}
}

// Write writes a header to an io.Writer
func (s *Serializer) Write(w io.Writer, header *Header) error {
	if err := s.validator.ValidateForSerialization(header); err != nil {
		return fmt.Errorf("serialization validation failed: %w", err)
	}

	data := s.Marshal(header)
	n, err := w.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write header data: %w", err)
	}

	if n != len(data) {
		return fmt.Errorf("incomplete write: expected %d bytes, wrote %d", len(data), n)
	}

	return nil
}

// Marshal marshals a header to a byte slice
func (s *Serializer) Marshal(h *Header) []byte {
	data := make([]byte, 0, TotalHeaderSize)

	data = append(data, h.magic[:]...)
	data = append(data, utils.ToBytes(h.version)...)
	data = append(data, utils.ToBytes(h.flags)...)
	data = append(data, h.salt[:]...)
	data = append(data, utils.ToBytes(h.originalSize)...)
	data = append(data, h.integrityHash[:]...)
	data = append(data, h.authTag[:]...)
	data = append(data, utils.ToBytes(h.checksum)...)
	data = append(data, h.padding[:]...)

	return data
}
