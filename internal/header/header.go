// Package header provides functionality for creating, reading, and writing authenticated file headers.
package header

import (
	"fmt"

	"github.com/hambosto/sweetbyte/internal/utils"
)

// Header format constants
const (
	MagicBytes = "SWX4"
	MagicSize  = 4
	MACSize    = 32 // HMAC-SHA256 output size
)

// TLV record tag constants
const (
	TagVersion      uint16 = 0x0001
	TagFlags        uint16 = 0x0002
	TagOriginalSize uint16 = 0x0004
)

// Version and flag constants
const (
	CurrentVersion uint16 = 0x0001
	FlagCompressed uint32 = 1 << 0
	FlagEncrypted  uint32 = 1 << 1
	DefaultFlags          = FlagCompressed | FlagEncrypted
)

// Limits for security and sanity checks
const (
	MaxAuthDataSize = 1024 * 1024 // 1MB limit for header size
	MaxRecordSize   = 64 * 1024   // 64KB limit for individual records
)

// Header represents a file header composed of extensible TLV (Tag-Length-Value) records.
// It provides authenticated storage of metadata using HMAC-SHA256.
type Header struct {
	records map[uint16][]byte
}

// New creates a new Header with essential metadata.
// The originalSize parameter specifies the uncompressed size of the file content.
func New(originalSize uint64) (*Header, error) {
	if originalSize == 0 {
		return nil, fmt.Errorf("original size cannot be zero")
	}

	h := &Header{
		records: make(map[uint16][]byte),
	}

	// Set mandatory fields
	h.records[TagVersion] = utils.ToBytes(CurrentVersion)
	h.records[TagFlags] = utils.ToBytes(DefaultFlags)
	h.records[TagOriginalSize] = utils.ToBytes(originalSize)

	return h, nil
}

// GetUint16 retrieves and converts a uint16 value by its tag.
func (h *Header) GetUint16(tag uint16) (uint16, error) {
	val, ok := h.records[tag]
	if !ok {
		return 0, fmt.Errorf("tag %d not found in header", tag)
	}

	if len(val) != 2 {
		return 0, fmt.Errorf("invalid uint16 value length for tag %d: expected 2 bytes, got %d", tag, len(val))
	}

	return utils.FromBytes[uint16](val), nil
}

// GetUint32 retrieves and converts a uint32 value by its tag.
func (h *Header) GetUint32(tag uint16) (uint32, error) {
	val, ok := h.records[tag]
	if !ok {
		return 0, fmt.Errorf("tag %d not found in header", tag)
	}

	if len(val) != 4 {
		return 0, fmt.Errorf("invalid uint32 value length for tag %d: expected 4 bytes, got %d", tag, len(val))
	}

	return utils.FromBytes[uint32](val), nil
}

// GetUint64 retrieves and converts a uint64 value by its tag.
func (h *Header) GetUint64(tag uint16) (uint64, error) {
	val, ok := h.records[tag]
	if !ok {
		return 0, fmt.Errorf("tag %d not found in header", tag)
	}

	if len(val) != 8 {
		return 0, fmt.Errorf("invalid uint64 value length for tag %d: expected 8 bytes, got %d", tag, len(val))
	}

	return utils.FromBytes[uint64](val), nil
}

// OriginalSize returns the original uncompressed file size.
func (h *Header) OriginalSize() (uint64, error) {
	return h.GetUint64(TagOriginalSize)
}
