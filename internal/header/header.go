// Package header provides functionality for handling file headers,
// including serialization and deserialization of metadata.
package header

import (
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/config"
)

const (
	// MagicBytes is the constant string "SWX4" that identifies the file format.
	MagicBytes = "SWX4"
	// MagicSize is the size of the magic bytes (4 bytes).
	MagicSize = 4
	// MACSize is the size of the HMAC-SHA256 message authentication code (32 bytes).
	MACSize = 32
	// HeaderDataSize is the fixed size of the core header data section (14 bytes).
	// It includes Version (2), Flags (4), and OriginalSize (8).
	HeaderDataSize = 14
	// CurrentVersion is the latest version of the header format.
	CurrentVersion = 0x0001
	// FlagCompressed indicates that the file content is compressed.
	FlagCompressed = 1 << 0
	// FlagEncrypted indicates that the file content is encrypted.
	FlagEncrypted = 1 << 1
	// DefaultFlags sets the default file processing options to compressed and encrypted.
	DefaultFlags = FlagCompressed | FlagEncrypted
)

// Header represents the metadata at the beginning of a file.
// It contains information about the file format version, compression/encryption flags,
// and the original size of the content.
type Header struct {
	Version      uint16 // The version of the header format.
	Flags        uint32 // Bitmask for flags like compression and encryption.
	OriginalSize uint64 // The original size of the file content before any processing.

	// decodedSections holds the raw data of each header section after decoding.
	// This map is populated during unmarshaling and is used for MAC verification and accessing section data.
	decodedSections map[SectionType][]byte
}

// NewHeader creates a new Header with default values.
func NewHeader() (*Header, error) {
	return &Header{
		Version:      CurrentVersion,
		Flags:        DefaultFlags,
		OriginalSize: 0,
	}, nil
}

// GetOriginalSize returns the original size of the file content.
func (h *Header) GetOriginalSize() uint64 {
	return h.OriginalSize
}

// SetOriginalSize sets the original size of the file content.
func (h *Header) SetOriginalSize(size uint64) {
	h.OriginalSize = size
}

// IsCompressed checks if the compression flag is set.
func (h *Header) IsCompressed() bool {
	return h.Flags&FlagCompressed != 0
}

// IsEncrypted checks if the encryption flag is set.
func (h *Header) IsEncrypted() bool {
	return h.Flags&FlagEncrypted != 0
}

// SetCompressed sets or unsets the compression flag.
func (h *Header) SetCompressed(compressed bool) {
	if compressed {
		h.Flags |= FlagCompressed
	} else {
		h.Flags &^= FlagCompressed
	}
}

// SetEncrypted sets or unsets the encryption flag.
func (h *Header) SetEncrypted(encrypted bool) {
	if encrypted {
		h.Flags |= FlagEncrypted
	} else {
		h.Flags &^= FlagEncrypted
	}
}

// Validate checks if the header's fields have valid values.
func (h *Header) Validate() error {
	if h.Version > CurrentVersion {
		return fmt.Errorf("unsupported version: %d (current: %d)", h.Version, CurrentVersion)
	}
	if h.OriginalSize == 0 {
		return fmt.Errorf("original size cannot be zero")
	}
	return nil
}

// Marshal serializes the header into a byte slice.
// It uses a Serializer to handle the encoding and formatting.
func (h *Header) Marshal(salt, key []byte) ([]byte, error) {
	marshaler, err := NewSerializer(h)
	if err != nil {
		return nil, fmt.Errorf("failed to create serializer: %w", err)
	}
	return marshaler.Marshal(salt, key)
}

// Unmarshal deserializes the header from an io.Reader.
// It uses a Deserializer to handle the decoding and parsing.
func (h *Header) Unmarshal(r io.Reader) error {
	unmarshaler, err := NewDeserializer(h)
	if err != nil {
		return fmt.Errorf("failed to create deserializer: %w", err)
	}
	return unmarshaler.Unmarshal(r)
}

// Salt returns the salt from the decoded header sections.
// It returns an error if the header has not been unmarshalled yet.
func (h *Header) Salt() ([]byte, error) {
	if h.decodedSections == nil {
		return nil, fmt.Errorf("header not unmarshalled yet")
	}
	return h.decodedSections[SectionSalt][:config.SaltSize], nil
}

// Magic returns the magic bytes from the decoded header sections.
// It returns an error if the header has not been unmarshalled yet.
func (h *Header) Magic() ([]byte, error) {
	if h.decodedSections == nil {
		return nil, fmt.Errorf("header not unmarshalled yet")
	}
	return h.decodedSections[SectionMagic][:MagicSize], nil
}

// VerifyMAC computes the MAC of the header sections using the provided key
// and compares it with the MAC stored in the header.
// It returns an error if the MACs do not match or if the header has not been unmarshalled.
func (h *Header) VerifyMAC(key []byte) error {
	if h.decodedSections == nil {
		return fmt.Errorf("header not unmarshalled yet")
	}
	if len(key) == 0 {
		return fmt.Errorf("key cannot be empty")
	}
	// The MAC is computed over the magic, salt, and header data sections.
	return VerifyMAC(
		key,
		h.decodedSections[SectionMAC][:MACSize],
		h.decodedSections[SectionMagic][:MagicSize],
		h.decodedSections[SectionSalt][:config.SaltSize],
		h.decodedSections[SectionHeaderData][:HeaderDataSize],
	)
}
