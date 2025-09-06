// Package header provides functionalities for handling file headers.
package header

import (
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/utils"
)

// Unmarshal parses the header from the given reader and returns a Header struct.
func Unmarshal(r io.Reader, key, magic, salt []byte) (*Header, error) {
	// Ensure the key is not empty.
	if len(key) == 0 {
		return nil, fmt.Errorf("key cannot be empty")
	}

	// Read the header data.
	headerData := make([]byte, 14)
	if _, err := io.ReadFull(r, headerData); err != nil {
		return nil, fmt.Errorf("failed to read header data: %w", err)
	}

	// Read the header MAC.
	mac := make([]byte, MACSize)
	if _, err := io.ReadFull(r, mac); err != nil {
		return nil, fmt.Errorf("failed to read header MAC: %w", err)
	}

	// Verify the header MAC.
	if err := verifyMAC(key, mac, magic, salt, headerData); err != nil {
		return nil, err
	}

	// Deserialize the header data.
	h, err := deserialize(headerData)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize header: %w", err)
	}

	// Validate the header.
	if err := h.validate(); err != nil {
		return nil, err
	}

	return h, nil
}

// deserialize converts a byte slice into a Header struct.
func deserialize(data []byte) (*Header, error) {
	// Ensure the data has the correct size.
	if len(data) != 14 {
		return nil, fmt.Errorf("invalid header data size: expected 14 bytes, got %d", len(data))
	}

	// Create a new Header from the data.
	return &Header{
		Version:      utils.FromBytes[uint16](data[0:2]),
		Flags:        utils.FromBytes[uint32](data[2:6]),
		OriginalSize: utils.FromBytes[uint64](data[6:14]),
	}, nil
}
