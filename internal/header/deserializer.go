package header

import (
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/utils"
)

func Unmarshal(r io.Reader, key, magic, salt []byte) (*Header, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("key cannot be empty")
	}

	headerData := make([]byte, 14)
	if _, err := io.ReadFull(r, headerData); err != nil {
		return nil, fmt.Errorf("failed to read header data: %w", err)
	}

	mac := make([]byte, MACSize)
	if _, err := io.ReadFull(r, mac); err != nil {
		return nil, fmt.Errorf("failed to read header MAC: %w", err)
	}

	if err := verifyMAC(key, mac, magic, salt, headerData); err != nil {
		return nil, err
	}

	h, err := deserialize(headerData)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize header: %w", err)
	}

	if err := h.validate(); err != nil {
		return nil, err
	}

	return h, nil
}

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
