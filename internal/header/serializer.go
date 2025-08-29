package header

import (
	"bytes"
	"encoding/binary"
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

	// Enforce the maximum size limit for the authenticated data to prevent generating an invalid header.
	if len(authData) > MaxAuthDataSize {
		return nil, fmt.Errorf("auth data exceeds maximum allowed size: auth data size %d exceeds limit %d", len(authData), MaxAuthDataSize)
	}

	// Convert the length of the authenticated data to a 4-byte slice.
	authDataLenBytes := utils.ToBytes(uint32(len(authData)))

	// Compute the HMAC-SHA256 MAC. The MAC covers all preceding fields:
	// magic bytes, salt, authenticated data length, and the authenticated data itself.
	// This ensures that none of these fields can be altered without invalidating the MAC.
	mac, err := computeMAC(key, []byte(MagicBytes), salt, authDataLenBytes, authData)
	if err != nil {
		return nil, fmt.Errorf("failed to compute header MAC: %w", err)
	}

	// Assemble the final header by concatenating all parts in the correct order.
	// Pre-allocating the slice capacity improves performance by avoiding multiple reallocations.
	totalSize := MagicSize + len(salt) + 4 + len(authData) + MACSize
	result := make([]byte, 0, totalSize)

	result = append(result, []byte(MagicBytes)...) // 1. Magic bytes
	result = append(result, salt...)               // 2. Salt
	result = append(result, authDataLenBytes...)   // 3. Authenticated data length
	result = append(result, authData...)           // 4. Authenticated data (TLV records)
	result = append(result, mac...)                // 5. MAC

	return result, nil
}

// serializeRecords converts the header's internal map of TLV records into a
// concatenated byte slice. The iteration order over maps is not guaranteed,
// but this is acceptable because the MAC is computed over the final serialized data,
// preserving integrity regardless of order.
func (h *Header) serializeRecords() ([]byte, error) {
	// Use a bytes.Buffer for efficient concatenation.
	buf := new(bytes.Buffer)

	// Iterate over all records in the header's map.
	for tag, value := range h.records {
		// Enforce the maximum size limit for each individual record.
		if len(value) > MaxRecordSize {
			return nil, fmt.Errorf("record exceeds maximum allowed size: record with tag %d has size %d", tag, len(value))
		}

		// Write the 16-bit tag in big-endian format.
		if err := binary.Write(buf, binary.BigEndian, tag); err != nil {
			return nil, fmt.Errorf("failed to write tag %d: %w", tag, err)
		}

		// Write the 16-bit length of the value in big-endian format.
		if err := binary.Write(buf, binary.BigEndian, uint16(len(value))); err != nil {
			return nil, fmt.Errorf("failed to write length for tag %d: %w", tag, err)
		}

		// Write the actual value bytes.
		if _, err := buf.Write(value); err != nil {
			return nil, fmt.Errorf("failed to write value for tag %d: %w", tag, err)
		}
	}

	// Return the complete byte slice from the buffer.
	return buf.Bytes(), nil
}