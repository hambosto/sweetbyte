// Package header provides functionality for creating, reading, and writing
// authenticated file headers for the SweetByte application. The header contains
// essential metadata for processing the file, such as version, flags for
// compression and encryption, and the original file size.
//
// The header is designed to be fixed-size and is protected by an HMAC-SHA256
// message authentication code (MAC) to ensure its integrity and authenticity.
// This package handles the serialization and deserialization of the header,
// as well as MAC computation and verification.
package header

import (
	"bytes"
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/config"
)

// Constants defining the structure and properties of the file header.
const (
	// MagicBytes is a 4-byte sequence ("SWX4") that identifies the file format.
	// It serves as a quick check to ensure the file is of the expected type.
	MagicBytes = "SWX4"

	// MagicSize is the length of the magic byte sequence.
	MagicSize = 4

	// MACSize is the size of the HMAC-SHA256 output, which is 32 bytes.
	// This is used for authenticating the header.
	MACSize = 32
)

// Flag constants define bitmasks for various processing options.
// These flags are combined in the Header's Flags field.
const (
	// CurrentVersion represents the latest version of the file format.
	CurrentVersion uint16 = 0x0001

	// FlagCompressed indicates that the file content is compressed.
	FlagCompressed uint32 = 1 << 0 // Bit 0

	// FlagEncrypted indicates that the file content is encrypted.
	FlagEncrypted uint32 = 1 << 1 // Bit 1

	// DefaultFlags is the standard combination of flags for new files,
	// enabling both compression and encryption by default.
	DefaultFlags = FlagCompressed | FlagEncrypted
)

// Header represents the structured metadata of a SweetByte file.
// The binary layout of this struct is fixed and predictable, ensuring
// consistent serialization and deserialization across different systems.
// The total size of the serialized header data is 14 bytes.
//
// The layout is as follows:
// - Version (2 bytes): The file format version.
// - Flags (4 bytes): Bitmask for processing options like compression and encryption.
// - OriginalSize (8 bytes): The size of the original, uncompressed file.
type Header struct {
	Version      uint16 // File format version.
	Flags        uint32 // Processing flags (e.g., compression, encryption).
	OriginalSize uint64 // Original uncompressed file size in bytes.
}

// NewHeader creates a new Header with default values and the specified original size.
// It initializes the header with the current version and default flags.
// The originalSize must be greater than zero.
func NewHeader(originalSize uint64) (*Header, error) {
	// The original size of the file is a critical piece of metadata, so it cannot be zero.
	if originalSize == 0 {
		return nil, fmt.Errorf("original size cannot be zero")
	}

	// Return a new Header instance populated with standard values.
	return &Header{
		Version:      CurrentVersion,
		Flags:        DefaultFlags,
		OriginalSize: originalSize,
	}, nil
}

// validate checks that the header contains valid and supported field values.
// This is typically called after deserializing a header to ensure it's safe to use.
func (h *Header) validate() error {
	// Check if the header's version is newer than what this application supports.
	if h.Version > CurrentVersion {
		return fmt.Errorf("unsupported version: %d (current: %d)", h.Version, CurrentVersion)
	}
	// The original size must be a positive value.
	if h.OriginalSize == 0 {
		return fmt.Errorf("original size cannot be zero")
	}
	return nil
}

// ReadMagic reads the magic bytes from the given reader and returns them.
// It expects to read exactly MagicSize bytes.
func ReadMagic(r io.Reader) ([]byte, error) {
	magic := make([]byte, MagicSize)
	// io.ReadFull ensures that the entire buffer is filled.
	_, err := io.ReadFull(r, magic)
	return magic, err
}

// ReadSalt reads the salt from the given reader.
// The salt size is determined by the application's configuration.
func ReadSalt(r io.Reader) ([]byte, error) {
	salt := make([]byte, config.SaltSize)
	// io.ReadFull ensures that the entire buffer is filled.
	_, err := io.ReadFull(r, salt)
	return salt, err
}

// VerifyMagic compares the provided byte slice with the expected MagicBytes.
// It returns true if they match, indicating a valid file format.
func VerifyMagic(magic []byte) bool {
	return bytes.Equal(magic, []byte(MagicBytes))
}
