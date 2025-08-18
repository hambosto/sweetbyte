// Package header provides functionality for creating, reading, and writing file headers.
package header

import (
	"fmt"
	"io"
)

// Serializer handles serializing a header to a byte stream.
type Serializer struct{}

// NewSerializer creates a new Serializer.
func NewSerializer() *Serializer {
	return &Serializer{}
}

// Write writes a header to an io.Writer.
func (s *Serializer) Write(w io.Writer, header *Header) error {
	// Validate the header before writing.
	if err := s.Validate(header); err != nil {
		return fmt.Errorf("serialization validation failed: %w", err)
	}

	// Marshal the header to a byte slice.
	data := s.Marshal(header)
	// Write the data to the writer.
	n, err := w.Write(data)
	if err != nil {
		return fmt.Errorf("failed to write header data: %w", err)
	}

	// Check if the entire header was written.
	if n != len(data) {
		return fmt.Errorf("incomplete write: expected %d bytes, wrote %d", len(data), n)
	}

	return nil
}

// Validate validates the header fields before serialization.
func (s *Serializer) Validate(h *Header) error {
	// Validate the magic bytes.
	if !secureCompare(h.magic[:], []byte(MagicBytes)) {
		return fmt.Errorf("invalid magic bytes")
	}

	// Validate the version.
	if h.version == 0 {
		return fmt.Errorf("invalid version: %d", h.version)
	}

	// Validate the original size.
	if h.originalSize == 0 {
		return fmt.Errorf("original size cannot be zero")
	}

	// Validate the salt.
	zeroSalt := make([]byte, SaltSize)
	if secureCompare(h.salt[:], zeroSalt) {
		return fmt.Errorf("salt cannot be all zeros")
	}

	// Validate the integrity hash.
	zeroHash := make([]byte, IntegrityHashSize)
	if secureCompare(h.integrityHash[:], zeroHash) {
		return fmt.Errorf("integrity hash cannot be all zeros")
	}

	// Validate the auth tag.
	zeroAuth := make([]byte, AuthTagSize)
	if secureCompare(h.authTag[:], zeroAuth) {
		return fmt.Errorf("auth tag cannot be all zeros")
	}

	return nil
}

// Marshal marshals a header to a byte slice.
func (s *Serializer) Marshal(h *Header) []byte {
	data := make([]byte, 0, TotalHeaderSize)

	// Append all header fields to the byte slice.
	data = append(data, h.magic[:]...)
	data = append(data, uint16ToBytes(h.version)...)
	data = append(data, uint32ToBytes(h.flags)...)
	data = append(data, h.salt[:]...)
	data = append(data, uint64ToBytes(h.originalSize)...)
	data = append(data, h.integrityHash[:]...)
	data = append(data, h.authTag[:]...)
	data = append(data, uint32ToBytes(h.checksum)...)
	data = append(data, h.padding[:]...)

	return data
}
