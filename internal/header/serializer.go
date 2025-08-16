package header

import (
	"fmt"
	"io"
)

// Serializer handles header serialization to binary format
type Serializer struct{}

// NewSerializer creates a new serializer instance
func NewSerializer() *Serializer {
	return &Serializer{}
}

// Write serializes and writes the header to the writer
func (s *Serializer) Write(w io.Writer, header *Header) error {
	if err := s.Validate(header); err != nil {
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

// Validate ensures the header is ready for serialization
func (s *Serializer) Validate(h *Header) error {
	// Validate magic bytes
	if !secureCompare(h.magic[:], []byte(MagicBytes)) {
		return fmt.Errorf("invalid magic bytes")
	}

	// Validate version
	if h.version == 0 {
		return fmt.Errorf("invalid version: %d", h.version)
	}

	// Validate original size
	if h.originalSize == 0 {
		return fmt.Errorf("original size cannot be zero")
	}

	// Validate salt is not all zeros
	zeroSalt := make([]byte, SaltSize)
	if secureCompare(h.salt[:], zeroSalt) {
		return fmt.Errorf("salt cannot be all zeros")
	}

	// Validate integrity hash is not all zeros
	zeroHash := make([]byte, IntegrityHashSize)
	if secureCompare(h.integrityHash[:], zeroHash) {
		return fmt.Errorf("integrity hash cannot be all zeros")
	}

	// Validate auth tag is not all zeros
	zeroAuth := make([]byte, AuthTagSize)
	if secureCompare(h.authTag[:], zeroAuth) {
		return fmt.Errorf("auth tag cannot be all zeros")
	}

	return nil
}

// Marshal converts the header to binary format
func (s *Serializer) Marshal(h *Header) []byte {
	data := make([]byte, 0, TotalHeaderSize)

	// Serialize fields in exact order
	data = append(data, h.magic[:]...)                    // 4 bytes
	data = append(data, uint16ToBytes(h.version)...)      // 2 bytes
	data = append(data, uint32ToBytes(h.flags)...)        // 4 bytes
	data = append(data, h.salt[:]...)                     // 32 bytes
	data = append(data, uint64ToBytes(h.originalSize)...) // 8 bytes
	data = append(data, h.integrityHash[:]...)            // 32 bytes
	data = append(data, h.authTag[:]...)                  // 32 bytes
	data = append(data, uint32ToBytes(h.checksum)...)     // 4 bytes
	data = append(data, h.padding[:]...)                  // 16 bytes

	return data // Total: 134 bytes
}
