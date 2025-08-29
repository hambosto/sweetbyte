package header

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/utils"
)

// Marshal serializes the header into a byte slice, protecting it with HMAC-SHA256.
// The resulting format is: MagicBytes + Salt + AuthDataLength + AuthData + MAC
func (h *Header) Marshal(salt, key []byte) ([]byte, error) {
	if len(salt) != config.SaltSize {
		return nil, fmt.Errorf("invalid salt size: expected %d bytes, got %d", config.SaltSize, len(salt))
	}

	if len(key) == 0 {
		return nil, fmt.Errorf("key cannot be empty")
	}

	// Serialize TLV records
	authData, err := h.serializeRecords()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize records: %w", err)
	}

	if len(authData) > MaxAuthDataSize {
		return nil, fmt.Errorf("auth data exceeds maximum allowed size: auth data size %d exceeds limit %d", len(authData), MaxAuthDataSize)
	}

	authDataLenBytes := utils.ToBytes(uint32(len(authData)))

	// Compute MAC over magic bytes, salt, length, and auth data
	mac, err := computeMAC(key, []byte(MagicBytes), salt, authDataLenBytes, authData)
	if err != nil {
		return nil, fmt.Errorf("failed to compute header MAC: %w", err)
	}

	// Assemble final header: Magic + Salt + Length + AuthData + MAC
	totalSize := MagicSize + len(salt) + 4 + len(authData) + MACSize
	result := make([]byte, 0, totalSize)

	result = append(result, []byte(MagicBytes)...)
	result = append(result, salt...)
	result = append(result, authDataLenBytes...)
	result = append(result, authData...)
	result = append(result, mac...)

	return result, nil
}

// serializeRecords converts the TLV records map into a byte slice.
func (h *Header) serializeRecords() ([]byte, error) {
	buf := new(bytes.Buffer)

	for tag, value := range h.records {
		if len(value) > MaxRecordSize {
			return nil, fmt.Errorf("record exceeds maximum allowed size: record with tag %d has size %d", tag, len(value))
		}

		if err := binary.Write(buf, binary.BigEndian, tag); err != nil {
			return nil, fmt.Errorf("failed to write tag %d: %w", tag, err)
		}

		if err := binary.Write(buf, binary.BigEndian, uint16(len(value))); err != nil {
			return nil, fmt.Errorf("failed to write length for tag %d: %w", tag, err)
		}

		if _, err := buf.Write(value); err != nil {
			return nil, fmt.Errorf("failed to write value for tag %d: %w", tag, err)
		}
	}

	return buf.Bytes(), nil
}
