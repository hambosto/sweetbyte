package header

import (
	"fmt"
	"io"
)

type Serializer struct{}

func NewSerializer() *Serializer {
	return &Serializer{}
}

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

func (s *Serializer) Validate(h *Header) error {
	if !secureCompare(h.magic[:], []byte(MagicBytes)) {
		return fmt.Errorf("invalid magic bytes")
	}

	if h.version == 0 {
		return fmt.Errorf("invalid version: %d", h.version)
	}

	if h.originalSize == 0 {
		return fmt.Errorf("original size cannot be zero")
	}

	zeroSalt := make([]byte, SaltSize)
	if secureCompare(h.salt[:], zeroSalt) {
		return fmt.Errorf("salt cannot be all zeros")
	}

	zeroHash := make([]byte, IntegrityHashSize)
	if secureCompare(h.integrityHash[:], zeroHash) {
		return fmt.Errorf("integrity hash cannot be all zeros")
	}

	zeroAuth := make([]byte, AuthTagSize)
	if secureCompare(h.authTag[:], zeroAuth) {
		return fmt.Errorf("auth tag cannot be all zeros")
	}

	return nil
}

func (s *Serializer) Marshal(h *Header) []byte {
	data := make([]byte, 0, TotalHeaderSize)

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
