// Package header provides functionality for creating, reading, and writing file headers.
package header

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	// MagicBytes is the magic byte sequence for SweetByte files.
	MagicBytes = "SWX4"
	// MagicSize is the size of the magic byte sequence.
	MagicSize = 4
	// VersionSize is the size of the version field.
	VersionSize = 2
	// FlagsSize is the size of the flags field.
	FlagsSize = 4
	// SaltSize is the size of the salt field.
	SaltSize = 32
	// OriginalSizeSize is the size of the original size field.
	OriginalSizeSize = 8
	// IntegrityHashSize is the size of the integrity hash field.
	IntegrityHashSize = 32
	// AuthTagSize is the size of the authentication tag field.
	AuthTagSize = 32
	// ChecksumSize is the size of the checksum field.
	ChecksumSize = 4
	// PaddingSize is the size of the padding field.
	PaddingSize = 16
	// TotalHeaderSize is the total size of the header.
	TotalHeaderSize = 134
)

const (
	// CurrentVersion is the current version of the file format.
	CurrentVersion uint16 = 0x0001
	// FlagCompressed indicates that the file is compressed.
	FlagCompressed uint32 = 1 << 0
	// FlagEncrypted indicates that the file is encrypted.
	FlagEncrypted uint32 = 1 << 1
	// FlagIntegrityV2 indicates that the file uses the v2 integrity check.
	FlagIntegrityV2 uint32 = 1 << 2
	// FlagAntiTamper indicates that the file has anti-tampering protection.
	FlagAntiTamper uint32 = 1 << 3
	// DefaultFlags is the default set of flags for a new file.
	DefaultFlags = FlagEncrypted | FlagIntegrityV2 | FlagAntiTamper
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

// NewHeader creates a new Header.
func NewHeader(originalSize uint64, salt []byte, key []byte) (*Header, error) {
	// Validate the input parameters.
	if len(salt) != SaltSize {
		return nil, fmt.Errorf("salt must be exactly %d bytes", SaltSize)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("key cannot be empty")
	}
	if originalSize == 0 {
		return nil, fmt.Errorf("original size cannot be zero")
	}

	// Create a new header with default values.
	h := &Header{
		version:      CurrentVersion,
		flags:        DefaultFlags,
		originalSize: originalSize,
	}

	// Set the magic bytes and salt.
	copy(h.magic[:], []byte(MagicBytes))
	copy(h.salt[:], salt)

	// Generate random padding.
	if _, err := rand.Read(h.padding[:]); err != nil {
		return nil, fmt.Errorf("failed to generate padding: %w", err)
	}

	// Compute the protection fields.
	protector := NewProtector(key)
	if err := protector.ComputeAllProtection(h); err != nil {
		return nil, fmt.Errorf("failed to compute protection: %w", err)
	}

	return h, nil
}

// Read reads a header from an io.Reader.
func Read(r io.Reader) (*Header, error) {
	deserializer := NewDeserializer()
	return deserializer.Read(r)
}

// Write writes the header to an io.Writer.
func (h *Header) Write(w io.Writer) error {
	serializer := NewSerializer()
	return serializer.Write(w, h)
}

// Verify verifies the header's integrity and authenticity.
func (h *Header) Verify(key []byte) error {
	verifier := NewVerifier(key)
	return verifier.VerifyAll(h)
}

// Magic returns the magic bytes of the header.
func (h *Header) Magic() []byte {
	result := make([]byte, MagicSize)
	copy(result, h.magic[:])
	return result
}

// Version returns the version of the header.
func (h *Header) Version() uint16 {
	return h.version
}

// Flags returns the flags of the header.
func (h *Header) Flags() uint32 {
	return h.flags
}

// Salt returns the salt of the header.
func (h *Header) Salt() []byte {
	result := make([]byte, SaltSize)
	copy(result, h.salt[:])
	return result
}

// OriginalSize returns the original size of the file.
func (h *Header) OriginalSize() uint64 {
	return h.originalSize
}

// HasFlag checks if the header has a specific flag set.
func (h *Header) HasFlag(flag uint32) bool {
	return h.flags&flag != 0
}

// secureCompare performs a constant-time comparison of two byte slices.
func secureCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// uint64ToBytes converts a uint64 to a byte slice.
func uint64ToBytes(v uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, v)
	return buf
}

// uint32ToBytes converts a uint32 to a byte slice.
func uint32ToBytes(v uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, v)
	return buf
}

// uint16ToBytes converts a uint16 to a byte slice.
func uint16ToBytes(v uint16) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, v)
	return buf
}

// bytesToUint64 converts a byte slice to a uint64.
func bytesToUint64(b []byte) uint64 {
	return binary.BigEndian.Uint64(b)
}

// bytesToUint32 converts a byte slice to a uint32.
func bytesToUint32(b []byte) uint32 {
	return binary.BigEndian.Uint32(b)
}

// bytesToUint16 converts a byte slice to a uint16.
func bytesToUint16(b []byte) uint16 {
	return binary.BigEndian.Uint16(b)
}
