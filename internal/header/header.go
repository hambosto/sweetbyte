// Package header provides functionality for creating, reading, and writing file headers.
package header

import (
	"crypto/rand"
	"fmt"
	"io"
)

const (
	// MagicBytes is a 4-byte sequence that identifies the file type.
	MagicBytes = "SWX4"
	// MagicSize is the size of the magic bytes.
	MagicSize = 4
	// VersionSize is the size of the version field.
	VersionSize = 2
	// FlagsSize is the size of the flags field.
	FlagsSize = 4
	// SaltSize is the size of the salt used in key derivation.
	SaltSize = 32
	// OriginalSizeSize is the size of the original file size field.
	OriginalSizeSize = 8
	// AuthTagSize is the size of the authentication tag (HMAC-SHA256).
	AuthTagSize = 32
	// PaddingSize is the size of the random padding.
	PaddingSize = 16
	// TotalHeaderSize is the total size of the header in bytes.
	TotalHeaderSize = MagicSize + VersionSize + FlagsSize + SaltSize + OriginalSizeSize + AuthTagSize + PaddingSize
)

const (
	// CurrentVersion is the latest version of the header format.
	CurrentVersion uint16 = 0x0001
	// FlagCompressed indicates that the file content is compressed.
	FlagCompressed uint32 = 1 << 0
	// FlagEncrypted indicates that the file content is encrypted.
	FlagEncrypted uint32 = 1 << 1
	// DefaultFlags represents the standard set of flags applied to new headers.
	DefaultFlags = FlagEncrypted
)

// Header represents the structured data at the beginning of a SweetByte file.
// It contains metadata and security information essential for file processing.
// The fields are private and accessed via getter methods to ensure immutability.
type Header struct {
	magic        [MagicSize]byte
	version      uint16
	flags        uint32
	salt         [SaltSize]byte
	originalSize uint64
	authTag      [AuthTagSize]byte
	padding      [PaddingSize]byte
}

// NewHeader creates a new Header with the given parameters.
// It initializes the header with default values, generates random padding,
// and computes the authentication tag.
func NewHeader(originalSize uint64, salt []byte, key []byte) (*Header, error) {
	if len(salt) != SaltSize {
		return nil, fmt.Errorf("salt must be exactly %d bytes", SaltSize)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("key cannot be empty")
	}
	if originalSize == 0 {
		return nil, fmt.Errorf("original size cannot be zero")
	}

	header := &Header{
		version:      CurrentVersion,
		flags:        DefaultFlags,
		originalSize: originalSize,
	}

	copy(header.magic[:], []byte(MagicBytes))
	copy(header.salt[:], salt)

	if _, err := rand.Read(header.padding[:]); err != nil {
		return nil, fmt.Errorf("failed to generate padding: %w", err)
	}

	protector := NewProtector(key)
	if err := protector.Protect(header); err != nil {
		return nil, fmt.Errorf("failed to protect header: %w", err)
	}

	return header, nil
}

// Write serializes the header to an io.Writer.
func (h *Header) Write(w io.Writer) error {
	writer := NewWriter()
	return writer.Write(w, h)
}

// Verify checks the integrity and authenticity of the header using a provided key.
func (h *Header) Verify(key []byte) error {
	verifier := NewVerifier(key)
	return verifier.Verify(h)
}

// Magic returns a copy of the magic bytes.
func (h *Header) Magic() []byte {
	result := make([]byte, MagicSize)
	copy(result, h.magic[:])
	return result
}

// Version returns the header version.
func (h *Header) Version() uint16 {
	return h.version
}

// Flags returns the header flags.
func (h *Header) Flags() uint32 {
	return h.flags
}

// Salt returns a copy of the salt.
func (h *Header) Salt() []byte {
	result := make([]byte, SaltSize)
	copy(result, h.salt[:])
	return result
}

// OriginalSize returns the original size of the file.
func (h *Header) OriginalSize() uint64 {
	return h.originalSize
}

// AuthTag returns a copy of the authentication tag.
func (h *Header) AuthTag() []byte {
	result := make([]byte, AuthTagSize)
	copy(result, h.authTag[:])
	return result
}

// Padding returns a copy of the padding.
func (h *Header) Padding() []byte {
	result := make([]byte, PaddingSize)
	copy(result, h.padding[:])
	return result
}

// HasFlag checks if a specific flag is set in the header.
func (h *Header) HasFlag(flag uint32) bool {
	return h.flags&flag != 0
}
