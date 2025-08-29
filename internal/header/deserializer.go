package header

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/utils"
)

// ReadMagic reads the magic bytes from the given reader.
func ReadMagic(r io.Reader) ([]byte, error) {
	magic := make([]byte, MagicSize)
	_, err := io.ReadFull(r, magic)
	return magic, err
}

// ReadSalt reads the salt from the given reader.
func ReadSalt(r io.Reader) ([]byte, error) {
	salt := make([]byte, config.SaltSize)
	_, err := io.ReadFull(r, salt)
	return salt, err
}

// Unmarshal reads and deserializes an authenticated header from an io.Reader.
// It assumes the magic bytes and salt have already been read and verified by the caller.
func Unmarshal(r io.Reader, key, magic, salt []byte) (*Header, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("key cannot be empty")
	}

	// Read authenticated data length
	var authDataLen uint32
	if err := binary.Read(r, binary.BigEndian, &authDataLen); err != nil {
		return nil, fmt.Errorf("failed to read auth data length: %w", err)
	}

	// Sanity check for auth data size
	if authDataLen > MaxAuthDataSize {
		return nil, fmt.Errorf("auth data exceeds maximum allowed size: auth data length %d exceeds limit %d", authDataLen, MaxAuthDataSize)
	}

	// Read authenticated data
	authData := make([]byte, authDataLen)
	if _, err := io.ReadFull(r, authData); err != nil {
		return nil, fmt.Errorf("failed to read auth data: %w", err)
	}

	// Read MAC
	mac := make([]byte, MACSize)
	if _, err := io.ReadFull(r, mac); err != nil {
		return nil, fmt.Errorf("failed to read header MAC: %w", err)
	}

	// Verify MAC
	authDataLenBytes := utils.ToBytes(authDataLen)
	if err := verifyMAC(key, mac, magic, salt, authDataLenBytes, authData); err != nil {
		return nil, err
	}

	// Parse TLV records from authenticated data
	h, err := parseRecords(authData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse records: %w", err)
	}

	// Validate mandatory fields
	if err := h.validate(); err != nil {
		return nil, err
	}

	return h, nil
}

// parseRecords parses TLV records from a byte slice.
func parseRecords(data []byte) (*Header, error) {
	h := &Header{records: make(map[uint16][]byte)}
	reader := bytes.NewReader(data)

	for reader.Len() > 0 {
		// Read tag
		var tag uint16
		if err := binary.Read(reader, binary.BigEndian, &tag); err != nil {
			return nil, fmt.Errorf("failed to parse record tag: %w", err)
		}

		// Read length
		var length uint16
		if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
			return nil, fmt.Errorf("failed to parse record length for tag %d: %w", tag, err)
		}

		// Validate record size
		if int(length) > MaxRecordSize {
			return nil, fmt.Errorf("record exceeds maximum allowed size: record with tag %d has size %d", tag, length)
		}

		// Read value
		value := make([]byte, length)
		if _, err := io.ReadFull(reader, value); err != nil {
			return nil, fmt.Errorf("failed to parse record value for tag %d: %w", tag, err)
		}

		// Store record (check for duplicates)
		if _, exists := h.records[tag]; exists {
			return nil, fmt.Errorf("duplicate record found for tag %d", tag)
		}
		h.records[tag] = value
	}

	return h, nil
}

// validate checks that the header contains all mandatory fields with correct formats.
func (h *Header) validate() error {
	// Check mandatory version field
	if _, ok := h.records[TagVersion]; !ok {
		return fmt.Errorf("header is missing mandatory version field")
	}

	// Validate version field size
	if version, err := h.GetUint16(TagVersion); err != nil {
		return fmt.Errorf("invalid version field: %w", err)
	} else if version > CurrentVersion {
		return fmt.Errorf("unsupported version: %d (current: %d)", version, CurrentVersion)
	}

	// Validate flags field if present
	if _, ok := h.records[TagFlags]; ok {
		if _, err := h.GetUint32(TagFlags); err != nil {
			return fmt.Errorf("invalid flags field: %w", err)
		}
	}

	// Validate original size field if present
	if _, ok := h.records[TagOriginalSize]; ok {
		if size, err := h.GetUint64(TagOriginalSize); err != nil {
			return fmt.Errorf("invalid original size field: %w", err)
		} else if size == 0 {
			return fmt.Errorf("original size cannot be zero")
		}
	}

	return nil
}
