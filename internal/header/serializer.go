package header

import (
	"fmt"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/utils"
)

// Marshal serializes the header into a byte slice, protecting it with an HMAC-SHA256 MAC.
// The resulting byte slice has the following structure:
// [MagicBytes (4 bytes)][Salt (variable size)][AuthDataLength (4 bytes)][AuthData (variable size)][MAC (32 bytes)]
// This structure ensures that the file type can be identified, the header's integrity can be verified,
// and the metadata can be securely parsed.
func (h *Header) Marshal(salt, key []byte) ([]byte, error) {
	// Validate the salt size to ensure it matches the configured length.
	if len(salt) != config.SaltSize {
		return nil, fmt.Errorf("invalid salt size: expected %d bytes, got %d", config.SaltSize, len(salt))
	}

	// A key is required to compute the HMAC.
	if len(key) == 0 {
		return nil, fmt.Errorf("key cannot be empty")
	}

	// Serialize the header's TLV records into a single byte slice (the "authenticated data").
	authData, err := h.serializeRecords()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize records: %w", err)
	}

	authDataLen := len(authData)
	// Enforce the maximum size limit for the authenticated data to prevent generating an invalid header.
	if authDataLen > MaxAuthDataSize {
		return nil, fmt.Errorf("auth data exceeds maximum allowed size: %d > %d", authDataLen, MaxAuthDataSize)
	}
	authDataLenBytes := utils.ToBytes(uint32(authDataLen))

	// Compute the HMAC-SHA256 MAC. The MAC covers all preceding fields:
	// magic bytes, salt, authenticated data length, and the authenticated data itself.
	mac, err := computeMAC(key, []byte(MagicBytes), salt, authDataLenBytes, authData)
	if err != nil {
		return nil, fmt.Errorf("failed to compute header MAC: %w", err)
	}

	// Assemble the final header in order.
	totalSize := MagicSize + len(salt) + 4 + len(authData) + MACSize
	result := make([]byte, 0, totalSize)

	result = append(result, []byte(MagicBytes)...) // 1. Magic bytes
	result = append(result, salt...)               // 2. Salt
	result = append(result, authDataLenBytes...)   // 3. Authenticated data length
	result = append(result, authData...)           // 4. Authenticated data
	result = append(result, mac...)                // 5. MAC

	return result, nil
}

// serializeRecords converts the header's internal map of TLV records into a
// concatenated byte slice using the utility functions for byte conversion.
func (h *Header) serializeRecords() ([]byte, error) {
	// First calculate the total size needed
	totalSize := 0
	for tag, value := range h.records {
		if len(value) > MaxRecordSize {
			return nil, fmt.Errorf("record exceeds maximum allowed size: record with tag %d has size %d", tag, len(value))
		}
		// 4 bytes for tag + 2 bytes for length + value length
		totalSize += 4 + 2 + len(value)
	}

	// Allocate the exact size
	result := make([]byte, 0, totalSize)

	// Append each record
	for tag, value := range h.records {
		result = append(result, utils.ToBytes(tag)...)
		// #nosec G115
		result = append(result, utils.ToBytes(uint16(len(value)))...)
		result = append(result, value...)
	}

	return result, nil
}
