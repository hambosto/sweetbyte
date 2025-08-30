package header

import (
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/utils"
)

// Unmarshal reads and deserializes an authenticated header from an io.Reader.
// It verifies the integrity using HMAC-SHA256 and deserializes the header data.
// Assumes magic bytes and salt have already been read.
func Unmarshal(r io.Reader, key, magic, salt []byte) (*Header, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("key cannot be empty")
	}

	// Read the fixed-size header data (14 bytes)
	headerData := make([]byte, 14)
	if _, err := io.ReadFull(r, headerData); err != nil {
		return nil, fmt.Errorf("failed to read header data: %w", err)
	}

	// Read the MAC
	mac := make([]byte, MACSize)
	if _, err := io.ReadFull(r, mac); err != nil {
		return nil, fmt.Errorf("failed to read header MAC: %w", err)
	}

	// Verify MAC
	if err := verifyMAC(key, mac, magic, salt, headerData); err != nil {
		return nil, err
	}

	// Deserialize header data
	h, err := deserialize(headerData)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize header: %w", err)
	}

	// Validate the deserialized header
	if err := h.validate(); err != nil {
		return nil, err
	}

	return h, nil
}

// deserialize converts binary data back to a Header struct.
func deserialize(data []byte) (*Header, error) {
	if len(data) != 14 {
		return nil, fmt.Errorf("invalid header data size: expected 14 bytes, got %d", len(data))
	}

	return &Header{
		Version:      utils.FromBytes[uint16](data[0:2]),
		Flags:        utils.FromBytes[uint32](data[2:6]),
		OriginalSize: utils.FromBytes[uint64](data[6:14]),
	}, nil
}
