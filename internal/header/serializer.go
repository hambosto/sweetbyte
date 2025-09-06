package header

import (
	"fmt"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/utils"
)

func (h *Header) Marshal(salt, key []byte) ([]byte, error) {
	if err := h.validate(); err != nil {
		return nil, fmt.Errorf("header validation failed: %w", err)
	}

	if len(salt) != config.SaltSize {
		return nil, fmt.Errorf("invalid salt size: expected %d bytes, got %d", config.SaltSize, len(salt))
	}

	if len(key) == 0 {
		return nil, fmt.Errorf("key cannot be empty")
	}

	headerData := h.serialize()
	mac, err := computeMAC(key, []byte(MagicBytes), salt, headerData)
	if err != nil {
		return nil, fmt.Errorf("failed to compute header MAC: %w", err)
	}

	totalSize := MagicSize + len(salt) + len(headerData) + MACSize
	result := make([]byte, 0, totalSize)
	result = append(result, []byte(MagicBytes)...)
	result = append(result, salt...)
	result = append(result, headerData...)
	result = append(result, mac...)

	return result, nil
}

func (h *Header) serialize() []byte {
	var data []byte
	data = append(data, utils.ToBytes(h.Version)...)
	data = append(data, utils.ToBytes(h.Flags)...)
	data = append(data, utils.ToBytes(h.OriginalSize)...)
	return data
}
