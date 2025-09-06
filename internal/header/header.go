// Package header provides functionalities for handling file headers.
package header

import (
	"bytes"
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/config"
)

const (
	// MagicBytes is the magic byte sequence for sweetbyte files.
	MagicBytes = "SWX4"
	// MagicSize is the size of the magic byte sequence.
	MagicSize = 4
	// MACSize is the size of the header MAC.
	MACSize = 32
)

const (
	// CurrentVersion is the current version of the file format.
	CurrentVersion uint16 = 0x0001
	// FlagCompressed indicates that the file is compressed.
	FlagCompressed uint32 = 1 << 0 // Bit 0
	// FlagEncrypted indicates that the file is encrypted.
	FlagEncrypted uint32 = 1 << 1 // Bit 1
	// DefaultFlags is the default set of flags for a new header.
	DefaultFlags = FlagCompressed | FlagEncrypted
)

// Header represents the file header.
type Header struct {
	Version      uint16
	Flags        uint32
	OriginalSize uint64
}

// NewHeader creates a new Header with the given original size.
func NewHeader(originalSize uint64) (*Header, error) {
	// Ensure the original size is not zero.
	if originalSize == 0 {
		return nil, fmt.Errorf("original size cannot be zero")
	}

	// Create a new header with default values.
	return &Header{
		Version:      CurrentVersion,
		Flags:        DefaultFlags,
		OriginalSize: originalSize,
	}, nil
}

// validate checks if the header is valid.
func (h *Header) validate() error {
	// Check if the version is supported.
	if h.Version > CurrentVersion {
		return fmt.Errorf("unsupported version: %d (current: %d)", h.Version, CurrentVersion)
	}

	// Check if the original size is not zero.
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

// VerifyMagic checks if the given magic bytes are valid.
func VerifyMagic(magic []byte) bool {
	return bytes.Equal(magic, []byte(MagicBytes))
}
