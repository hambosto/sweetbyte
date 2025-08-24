// Package header provides functionality for creating, reading, and writing file headers.
package header

import (
	"crypto/rand"
	"fmt"
	"io"
)

// Constants for header structure
const (
	MagicBytes        = "SWX4"
	MagicSize         = 4
	VersionSize       = 2
	FlagsSize         = 4
	SaltSize          = 32
	OriginalSizeSize  = 8
	IntegrityHashSize = 32
	AuthTagSize       = 32
	ChecksumSize      = 4
	PaddingSize       = 16
	TotalHeaderSize   = 134
)

// Version and flag constants
const (
	CurrentVersion  uint16 = 0x0001
	FlagCompressed  uint32 = 1 << 0
	FlagEncrypted   uint32 = 1 << 1
	FlagIntegrityV2 uint32 = 1 << 2
	FlagAntiTamper  uint32 = 1 << 3
	DefaultFlags           = FlagEncrypted | FlagIntegrityV2 | FlagAntiTamper
)

// Header represents the header of a SweetByte file.
type Header struct {
	magic         [MagicSize]byte
	version       uint16
	flags         uint32
	salt          [SaltSize]byte
	originalSize  uint64
	integrityHash [IntegrityHashSize]byte
	authTag       [AuthTagSize]byte
	checksum      uint32
	padding       [PaddingSize]byte
}

// NewHeader creates a new Header with the given parameters
func NewHeader(originalSize uint64, salt []byte, key []byte) (*Header, error) {
	if err := validateNewHeaderParams(originalSize, salt, key); err != nil {
		return nil, err
	}

	header := &Header{
		version:      CurrentVersion,
		flags:        DefaultFlags,
		originalSize: originalSize,
	}

	// Set magic bytes and salt
	copy(header.magic[:], []byte(MagicBytes))
	copy(header.salt[:], salt)

	// Generate random padding
	if err := generatePadding(header); err != nil {
		return nil, err
	}

	// Compute protection fields
	protector := NewProtector(key)
	if err := protector.ComputeAllProtection(header); err != nil {
		return nil, fmt.Errorf("failed to compute protection: %w", err)
	}

	return header, nil
}

// Read reads a header from an io.Reader
func Read(r io.Reader) (*Header, error) {
	deserializer := NewDeserializer()
	return deserializer.Read(r)
}

// Write writes the header to an io.Writer
func (h *Header) Write(w io.Writer) error {
	serializer := NewSerializer()
	return serializer.Write(w, h)
}

// Verify verifies the header's integrity and authenticity
func (h *Header) Verify(key []byte) error {
	verifier := NewVerifier(key)
	return verifier.VerifyAll(h)
}

// Getter methods
func (h *Header) Magic() []byte {
	result := make([]byte, MagicSize)
	copy(result, h.magic[:])
	return result
}

func (h *Header) Version() uint16 {
	return h.version
}

func (h *Header) Flags() uint32 {
	return h.flags
}

func (h *Header) Salt() []byte {
	result := make([]byte, SaltSize)
	copy(result, h.salt[:])
	return result
}

func (h *Header) OriginalSize() uint64 {
	return h.originalSize
}

func (h *Header) HasFlag(flag uint32) bool {
	return h.flags&flag != 0
}

// Helper functions for header creation
func validateNewHeaderParams(originalSize uint64, salt []byte, key []byte) error {
	if len(salt) != SaltSize {
		return fmt.Errorf("salt must be exactly %d bytes", SaltSize)
	}
	if len(key) == 0 {
		return fmt.Errorf("key cannot be empty")
	}
	if originalSize == 0 {
		return fmt.Errorf("original size cannot be zero")
	}
	return nil
}

func generatePadding(header *Header) error {
	if _, err := rand.Read(header.padding[:]); err != nil {
		return fmt.Errorf("failed to generate padding: %w", err)
	}
	return nil
}
