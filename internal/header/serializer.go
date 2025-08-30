// Package header provides functionality for creating, reading, and writing
// authenticated file headers using direct struct serialization.
package header

import (
	"fmt"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/utils"
)

// Marshal serializes the Header struct into a byte slice that includes
// authentication information. The resulting byte slice is structured to be
// easily written to a file or stream.
//
// The structure of the marshaled header is as follows:
// [MagicBytes (4 bytes)][Salt (variable size)][HeaderData (14 bytes)][MAC (32 bytes)]
//
// The process involves:
// 1. Validating the header's fields.
// 2. Serializing the core Header struct into a 14-byte slice.
// 3. Computing an HMAC-SHA256 MAC over the magic bytes, salt, and serialized header data.
// 4. Assembling the final byte slice in the correct order.
//
// This ensures that the header is both structured and authenticated, protecting
// it from tampering.
func (h *Header) Marshal(salt, key []byte) ([]byte, error) {
	// First, validate the header's contents to ensure they are valid before serialization.
	if err := h.validate(); err != nil {
		return nil, fmt.Errorf("header validation failed: %w", err)
	}

	// Ensure the provided salt has the correct size as defined in the configuration.
	if len(salt) != config.SaltSize {
		return nil, fmt.Errorf("invalid salt size: expected %d bytes, got %d", config.SaltSize, len(salt))
	}

	// A key is required to compute the HMAC.
	if len(key) == 0 {
		return nil, fmt.Errorf("key cannot be empty")
	}

	// Serialize the header fields (Version, Flags, OriginalSize) into a binary format.
	headerData := h.serialize()

	// Compute the HMAC-SHA256 MAC. The MAC covers the magic bytes, salt, and the
	// serialized header data. This authenticates the entire header block.
	mac, err := computeMAC(key, []byte(MagicBytes), salt, headerData)
	if err != nil {
		return nil, fmt.Errorf("failed to compute header MAC: %w", err)
	}

	// Assemble the final byte slice in the correct order.
	// Pre-allocating the slice with the total size improves efficiency.
	totalSize := MagicSize + len(salt) + len(headerData) + MACSize
	result := make([]byte, 0, totalSize)
	result = append(result, []byte(MagicBytes)...) // Prepend magic bytes.
	result = append(result, salt...)               // Append the salt.
	result = append(result, headerData...)         // Append the serialized header data.
	result = append(result, mac...)                // Append the computed MAC.

	return result, nil
}

// serialize converts the Header struct's fields into a 14-byte slice.
// It uses utility functions to perform the conversion from integer types
// to byte slices, likely using big-endian encoding for consistency.
//
// The layout of the returned byte slice is:
// - Version (2 bytes)
// - Flags (4 bytes)
// - OriginalSize (8 bytes)
func (h *Header) serialize() []byte {
	// Initialize an empty byte slice that will be built up.
	var data []byte

	// Append the byte representation of each field in order.
	data = append(data, utils.ToBytes(h.Version)...)
	data = append(data, utils.ToBytes(h.Flags)...)
	data = append(data, utils.ToBytes(h.OriginalSize)...)

	return data
}
