// Package header provides functionality for handling file headers,
// including serialization and deserialization of metadata.
package header

import (
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/config"
)

const (
	// MagicBytes is a unique identifier for the file format.
	MagicBytes = uint32(0xCAFEBABE)
	// MagicSize is the size of the magic bytes (4 bytes).
	MagicSize = 4
	// MACSize is the size of the HMAC-SHA256 message authentication code (32 bytes).
	MACSize = 32
	// HeaderDataSize is the fixed size of the core header data section (14 bytes).
	// It includes Version (2), Flags (4), and OriginalSize (8).
	HeaderDataSize = 14
	// CurrentVersion is the latest version of the header format.
	CurrentVersion = 0x0001
	// FlagProtected indicates that the file content is protected (encrypted and compressed).
	FlagProtected = 1 << 0
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

// IsProtected checks if the protected flag is set.
func (h *Header) IsProtected() bool {
	return h.Flags&FlagProtected != 0
}

// SetProtected sets or unsets the protected flag.
func (h *Header) SetProtected(protected bool) {
	if protected {
		h.Flags |= FlagProtected
	} else {
		h.Flags &^= FlagProtected
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
	return h.section(SectionSalt, config.SaltSize)
}

// Magic returns the magic bytes from the decoded header sections.
// It returns an error if the header has not been unmarshalled yet.
func (h *Header) Magic() ([]byte, error) {
	return h.section(SectionMagic, MagicSize)
}

// Verify computes the MAC of the header sections using the provided key
// and compares it with the MAC stored in the header.
// It returns an error if the MACs do not match or if the header has not been unmarshalled.
func (h *Header) Verify(key []byte) error {
	if len(key) == 0 {
		return fmt.Errorf("key cannot be empty")
	}

	expectedMAC, err := h.section(SectionMAC, MACSize)
	if err != nil {
		return err
	}
	magic, err := h.section(SectionMagic, MagicSize)
	if err != nil {
		return err
	}
	salt, err := h.section(SectionSalt, config.SaltSize)
	if err != nil {
		return err
	}
	headerData, err := h.section(SectionHeaderData, HeaderDataSize)
	if err != nil {
		return err
	}

	// The MAC is computed over the magic, salt, and header data sections.
	return VerifyMAC(
		key,
		expectedMAC,
		magic,
		salt,
		headerData,
	)
}

// section returns a decoded section, checking for presence and minimum length.
func (h *Header) section(st SectionType, minLen int) ([]byte, error) {
	if h.decodedSections == nil {
		return nil, fmt.Errorf("header not unmarshalled yet")
	}
	data, ok := h.decodedSections[st]
	if !ok || data == nil {
		return nil, fmt.Errorf("required section missing or nil")
	}
	if len(data) < minLen {
		return nil, fmt.Errorf("section too short")
	}
	return data[:minLen], nil
}
