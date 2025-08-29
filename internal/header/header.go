// Package header provides functionality for creating, reading, and writing
// authenticated file headers. The header format is designed to be extensible,
// secure, and efficient, using a Tag-Length-Value (TLV) structure for metadata
// and HMAC-SHA256 for authentication.
package header

import (
	"fmt"

	"github.com/hambosto/sweetbyte/internal/utils"
)

// Header format constants define the fixed-size elements of the file header.
const (
	// MagicBytes is a 4-byte sequence ("SWX4") that identifies the file format.
	MagicBytes = "SWX4"
	// MagicSize is the length of the magic byte sequence.
	MagicSize = 4
	// MACSize is the size of the HMAC-SHA256 Message Authentication Code in bytes.
	MACSize = 32 // HMAC-SHA256 output size
)

// TLV record tag constants define unique identifiers for each metadata field
// stored within the header's authenticated data section.
const (
	// TagVersion identifies the file format version.
	TagVersion uint16 = 0x0001
	// TagFlags stores bitwise flags for processing options (e.g., compression, encryption).
	TagFlags uint16 = 0x0002
	// TagOriginalSize stores the original, uncompressed size of the file content.
	TagOriginalSize uint16 = 0x0004
)

// Version and flag constants provide values for the corresponding TLV records.
const (
	// CurrentVersion is the latest version of the file format that this package supports.
	CurrentVersion uint16 = 0x0001
	// FlagCompressed indicates that the file content is compressed.
	FlagCompressed uint32 = 1 << 0
	// FlagEncrypted indicates that the file content is encrypted.
	FlagEncrypted uint32 = 1 << 1
	// DefaultFlags is the standard combination of flags for new files.
	DefaultFlags = FlagCompressed | FlagEncrypted
)

// Limits for security and sanity checks to prevent resource exhaustion attacks.
const (
	// MaxAuthDataSize defines the maximum allowed size for the entire authenticated
	// data block, preventing denial-of-service via oversized headers.
	MaxAuthDataSize = 1024 * 1024 // 1MB limit for header size
	// MaxRecordSize defines the maximum allowed size for a single TLV record's value.
	MaxRecordSize = 64 * 1024 // 64KB limit for individual records
)

// Header represents a file header composed of extensible TLV (Tag-Length-Value) records.
// It provides authenticated storage of metadata using HMAC-SHA256.
// The internal `records` map stores the raw byte values of the metadata, keyed by their tags.
type Header struct {
	records map[uint16][]byte
}

// NewHeader creates a new Header with essential metadata.
// It initializes the header with the current version, default flags, and the specified original file size.
// The originalSize parameter specifies the uncompressed size of the file content.
func NewHeader(originalSize uint64) (*Header, error) {
	// An original size of zero is considered invalid, as there would be no content to process.
	if originalSize == 0 {
		return nil, fmt.Errorf("original size cannot be zero")
	}

	// Initialize the header with a map to store TLV records.
	h := &Header{
		records: make(map[uint16][]byte),
	}

	// Set mandatory fields with their default values.
	// These values are converted to byte slices for storage.
	h.records[TagVersion] = utils.ToBytes(CurrentVersion)
	h.records[TagFlags] = utils.ToBytes(DefaultFlags)
	h.records[TagOriginalSize] = utils.ToBytes(originalSize)

	return h, nil
}

// GetUint16 retrieves a record by its tag and converts its value to a uint16.
// It returns an error if the tag is not found or if the value has an incorrect length.
func (h *Header) GetUint16(tag uint16) (uint16, error) {
	// Retrieve the raw byte value from the records map.
	val, ok := h.records[tag]
	if !ok {
		return 0, fmt.Errorf("tag %d not found in header", tag)
	}

	// A uint16 must be exactly 2 bytes long.
	if len(val) != 2 {
		return 0, fmt.Errorf("invalid uint16 value length for tag %d: expected 2 bytes, got %d", tag, len(val))
	}

	// Convert the byte slice to a uint16 and return it.
	return utils.FromBytes[uint16](val), nil
}

// GetUint32 retrieves a record by its tag and converts its value to a uint32.
// It returns an error if the tag is not found or if the value has an incorrect length.
func (h *Header) GetUint32(tag uint16) (uint32, error) {
	// Retrieve the raw byte value from the records map.
	val, ok := h.records[tag]
	if !ok {
		return 0, fmt.Errorf("tag %d not found in header", tag)
	}

	// A uint32 must be exactly 4 bytes long.
	if len(val) != 4 {
		return 0, fmt.Errorf("invalid uint32 value length for tag %d: expected 4 bytes, got %d", tag, len(val))
	}

	// Convert the byte slice to a uint32 and return it.
	return utils.FromBytes[uint32](val), nil
}

// GetUint64 retrieves a record by its tag and converts its value to a uint64.
// It returns an error if the tag is not found or if the value has an incorrect length.
func (h *Header) GetUint64(tag uint16) (uint64, error) {
	// Retrieve the raw byte value from the records map.
	val, ok := h.records[tag]
	if !ok {
		return 0, fmt.Errorf("tag %d not found in header", tag)
	}

	// A uint64 must be exactly 8 bytes long.
	if len(val) != 8 {
		return 0, fmt.Errorf("invalid uint64 value length for tag %d: expected 8 bytes, got %d", tag, len(val))
	}

	// Convert the byte slice to a uint64 and return it.
	return utils.FromBytes[uint64](val), nil
}

// OriginalSize is a convenience method that retrieves the original, uncompressed file size
// from the header. It is a wrapper around GetUint64 with the specific tag for original size.
func (h *Header) OriginalSize() (uint64, error) {
	return h.GetUint64(TagOriginalSize)
}