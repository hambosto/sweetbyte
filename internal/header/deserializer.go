
// Package header provides functionality for creating, reading, and writing
// authenticated file headers using direct struct serialization.
package header

import (
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/utils"
)

// Unmarshal reads and deserializes an authenticated header from an io.Reader.
// It verifies the integrity of the header using HMAC-SHA256 by re-calculating
// the MAC with the provided key, magic bytes, and salt. If the MAC is valid,
// it deserializes the header data into a Header struct.
//
// This function assumes that the magic bytes and salt have already been read
// from the reader and are passed as arguments.
//
// The process is as follows:
// 1. Read the fixed-size header data (14 bytes).
// 2. Read the HMAC-SHA256 MAC (32 bytes).
// 3. Verify the MAC by re-computing it using the key, magic bytes, salt, and header data.
// 4. If the MAC is valid, deserialize the header data into a Header struct.
// 5. Validate the fields of the deserialized header (e.g., version, original size).
//
// Returns a pointer to the deserialized Header struct or an error if any step fails.
func Unmarshal(r io.Reader, key, magic, salt []byte) (*Header, error) {
	// Ensure the key is not empty, as it's required for MAC verification.
	if len(key) == 0 {
		return nil, fmt.Errorf("key cannot be empty")
	}

	// Read the fixed-size header data (14 bytes). This contains the core metadata
	// like version, flags, and original file size.
	headerData := make([]byte, 14)
	if _, err := io.ReadFull(r, headerData); err != nil {
		return nil, fmt.Errorf("failed to read header data: %w", err)
	}

	// Read the MAC from the stream. The MAC is used to authenticate the header data.
	mac := make([]byte, MACSize)
	if _, err := io.ReadFull(r, mac); err != nil {
		return nil, fmt.Errorf("failed to read header MAC: %w", err)
	}

	// Verify the integrity and authenticity of the header by re-calculating the MAC
	// and comparing it with the one read from the stream.
	if err := verifyMAC(key, mac, magic, salt, headerData); err != nil {
		return nil, err // Return the error from verifyMAC directly.
	}

	// If the MAC is valid, deserialize the raw header data into a Header struct.
	h, err := deserialize(headerData)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize header: %w", err)
	}

	// Validate the contents of the deserialized header to ensure they are supported
	// and within expected ranges (e.g., version check).
	if err := h.validate(); err != nil {
		return nil, err
	}

	// Return the fully validated and deserialized header.
	return h, nil
}

// deserialize converts a 14-byte slice into a Header struct.
// The byte slice is expected to have the following layout:
// - Version (2 bytes, uint16)
// - Flags (4 bytes, uint32)
// - OriginalSize (8 bytes, uint64)
//
// This function uses utility functions to convert byte slices to their
// corresponding integer types in a generic way.
func deserialize(data []byte) (*Header, error) {
	// Ensure the input data has the exact expected size for a serialized header.
	if len(data) != 14 {
		return nil, fmt.Errorf("invalid header data size: expected 14 bytes, got %d", len(data))
	}

	// Construct the Header struct by slicing the data and converting each part.
	return &Header{
		Version:      utils.FromBytes[uint16](data[0:2]),   // First 2 bytes for Version.
		Flags:        utils.FromBytes[uint32](data[2:6]),   // Next 4 bytes for Flags.
		OriginalSize: utils.FromBytes[uint64](data[6:14]), // Last 8 bytes for OriginalSize.
	}, nil
}
