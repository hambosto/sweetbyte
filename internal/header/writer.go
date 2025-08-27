// Package header provides functionality for creating, reading, and writing file headers.
package header

import (
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/utils"
)

// Writer handles the conversion of a structured Header into a byte stream.
type Writer struct{}

// NewWriter creates and returns a new Writer instance.
func NewWriter() *Writer {
	return &Writer{}
}

// Write serializes a Header and writes it to an io.Writer.
func (s *Writer) Write(w io.Writer, header *Header) error {
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

// Marshal converts a Header struct into a byte slice.
func (s *Writer) Marshal(h *Header) []byte {
	data := make([]byte, 0, TotalHeaderSize)
	data = append(data, h.magic[:]...)
	data = append(data, utils.ToBytes(h.version)...)
	data = append(data, utils.ToBytes(h.flags)...)
	data = append(data, h.salt[:]...)
	data = append(data, utils.ToBytes(h.originalSize)...)
	data = append(data, h.authTag[:]...)
	data = append(data, h.padding[:]...)
	return data
}
