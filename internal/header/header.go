// Package header provides functionality for creating, reading, and writing
// authenticated file headers using direct struct serialization.
package header

import (
	"bytes"
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/config"
)

// Header format constants
const (
	MagicBytes = "SWX4"
	MagicSize  = 4
	MACSize    = 32 // HMAC-SHA256 output size
)

// Flag constants
const (
	CurrentVersion uint16 = 0x0001
	FlagCompressed uint32 = 1 << 0
	FlagEncrypted  uint32 = 1 << 1
	DefaultFlags          = FlagCompressed | FlagEncrypted
)

// Header represents a file header with structured metadata fields.
// The binary layout is fixed and predictable:
// Version (2 bytes) + Flags (4 bytes) + OriginalSize (8 bytes) = 14 bytes total
type Header struct {
	Version      uint16 // File format version
	Flags        uint32 // Processing flags (compression, encryption, etc.)
	OriginalSize uint64 // Original uncompressed file size
}

// NewHeader creates a new Header with essential metadata.
func NewHeader(originalSize uint64) (*Header, error) {
	if originalSize == 0 {
		return nil, fmt.Errorf("original size cannot be zero")
	}

	return &Header{
		Version:      CurrentVersion,
		Flags:        DefaultFlags,
		OriginalSize: originalSize,
	}, nil
}

// validate checks that the header contains valid field values.
func (h *Header) validate() error {
	if h.Version > CurrentVersion {
		return fmt.Errorf("unsupported version: %d (current: %d)", h.Version, CurrentVersion)
	}
	if h.OriginalSize == 0 {
		return fmt.Errorf("original size cannot be zero")
	}
	return nil
}

// ReadMagic reads the magic bytes from the given reader.
func ReadMagic(r io.Reader) ([]byte, error) {
	magic := make([]byte, MagicSize)
	_, err := io.ReadFull(r, magic)
	return magic, err
}

// ReadSalt reads the salt from the given reader.
func ReadSalt(r io.Reader) ([]byte, error) {
	salt := make([]byte, config.SaltSize)
	_, err := io.ReadFull(r, salt)
	return salt, err
}

func VerifyMagic(magic []byte) bool {
	return bytes.Equal(magic, []byte(MagicBytes))
}
