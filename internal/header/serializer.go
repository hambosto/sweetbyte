// Package header provides functionality for creating, reading, and writing file headers.
package header

import (
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/utils"
)

// Serializer handles the conversion of a structured Header into a byte stream.
// It ensures that the header is valid before serialization.
type Serializer struct {
	validator *Validator // A validator to check the header's integrity before writing.
}

// NewSerializer creates and returns a new Serializer instance.
func NewSerializer() *Serializer {
	return &Serializer{
		validator: NewValidator(),
	}
}

// Write serializes a Header and writes it to an io.Writer.
// It first validates the header, then marshals it into a byte slice, and finally writes the data.
// Returns an error if validation, writing, or the write operation itself fails.
func (s *Serializer) Write(w io.Writer, header *Header) error {
	// Validate the header to ensure all fields are correctly populated before serialization.
	if err := s.validator.ValidateForSerialization(header); err != nil {
		return fmt.Errorf("serialization validation failed: %w", err)
	}

	// Convert the Header struct to its byte representation.
	data := s.Marshal(header)
	// Write the byte data to the output stream.
	n, err := w.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write header data: %w", err)
	}

	// Check that the entire header was written.
	if n != len(data) {
		return fmt.Errorf("incomplete write: expected %d bytes, wrote %d", len(data), n)
	}

	return nil
}

// Marshal converts a Header struct into a byte slice.
// It concatenates the header fields in the correct order to produce the final byte representation.
func (s *Serializer) Marshal(h *Header) []byte {
	// Pre-allocate a slice with the exact size of the header for efficiency.
	data := make([]byte, 0, TotalHeaderSize)

	// Append each field to the byte slice in the specified order.
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
