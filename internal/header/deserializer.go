// Package header provides functionality for creating, reading, and writing authenticated file headers.
package header

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/utils"
)

// ReadMagic reads the magic bytes from the given reader and returns them.
// It is the caller's responsibility to verify that the magic bytes match the expected value.
func ReadMagic(r io.Reader) ([]byte, error) {
	// Allocate a buffer for the magic bytes.
	magic := make([]byte, MagicSize)
	// Read the magic bytes from the reader.
	_, err := io.ReadFull(r, magic)
	return magic, err
}

// ReadSalt reads the salt from the given reader.
// The salt is used in key derivation and MAC computation to ensure uniqueness.
func ReadSalt(r io.Reader) ([]byte, error) {
	// Allocate a buffer for the salt.
	salt := make([]byte, config.SaltSize)
	// Read the salt from the reader.
	_, err := io.ReadFull(r, salt)
	return salt, err
}

// Unmarshal reads and deserializes an authenticated header from an io.Reader.
// It verifies the integrity of the header using HMAC-SHA256 and parses the contained metadata.
// This function assumes the magic bytes and salt have already been read from the reader.
// The key must be the same key used during marshaling.
func Unmarshal(r io.Reader, key, magic, salt []byte) (*Header, error) {
	// The key is required for MAC verification.
	if len(key) == 0 {
		return nil, fmt.Errorf("key cannot be empty")
	}

	// Read the length of the authenticated data payload.
	// This length is a 32-bit unsigned integer in big-endian format.
	var authDataLen uint32
	if err := binary.Read(r, binary.BigEndian, &authDataLen); err != nil {
		return nil, fmt.Errorf("failed to read auth data length: %w", err)
	}

	// Perform a sanity check on the authenticated data size to prevent allocating excessive memory.
	if authDataLen > MaxAuthDataSize {
		return nil, fmt.Errorf("auth data exceeds maximum allowed size: auth data length %d exceeds limit %d", authDataLen, MaxAuthDataSize)
	}

	// Read the authenticated data payload itself.
	authData := make([]byte, authDataLen)
	if _, err := io.ReadFull(r, authData); err != nil {
		return nil, fmt.Errorf("failed to read auth data: %w", err)
	}

	// Read the Message Authentication Code (MAC) from the reader.
	mac := make([]byte, MACSize)
	if _, err := io.ReadFull(r, mac); err != nil {
		return nil, fmt.Errorf("failed to read header MAC: %w", err)
	}

	// Verify the MAC to ensure the header has not been tampered with.
	// The MAC is computed over the magic bytes, salt, authenticated data length, and the authenticated data itself.
	authDataLenBytes := utils.ToBytes(authDataLen)
	if err := verifyMAC(key, mac, magic, salt, authDataLenBytes, authData); err != nil {
		return nil, err
	}

	// If the MAC is valid, parse the TLV records from the authenticated data.
	h, err := parseRecords(authData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse records: %w", err)
	}

	// Validate the parsed header to ensure all mandatory fields are present and valid.
	if err := h.validate(); err != nil {
		return nil, err
	}

	return h, nil
}

// parseRecords parses a byte slice of concatenated TLV (Tag-Length-Value) records
// and populates a Header struct with the parsed data.
func parseRecords(data []byte) (*Header, error) {
	// Initialize a new Header and a reader for the raw data.
	h := &Header{records: make(map[uint16][]byte)}
	reader := bytes.NewReader(data)

	// Loop until all bytes from the reader have been consumed.
	for reader.Len() > 0 {
		// Read the 16-bit tag for the current record.
		var tag uint16
		if err := binary.Read(reader, binary.BigEndian, &tag); err != nil {
			return nil, fmt.Errorf("failed to parse record tag: %w", err)
		}

		// Read the 16-bit length for the current record's value.
		var length uint16
		if err := binary.Read(reader, binary.BigEndian, &length); err != nil {
			return nil, fmt.Errorf("failed to parse record length for tag %d: %w", tag, err)
		}

		// Sanity check the record size to prevent parsing overly large records.
		if int(length) > MaxRecordSize {
			return nil, fmt.Errorf("record exceeds maximum allowed size: record with tag %d has size %d", tag, length)
		}

		// Read the value of the record.
		value := make([]byte, length)
		if _, err := io.ReadFull(reader, value); err != nil {
			return nil, fmt.Errorf("failed to parse record value for tag %d: %w", tag, err)
		}

		// Store the record in the header's map.
		// Check for duplicate tags, as each tag must be unique.
		if _, exists := h.records[tag]; exists {
			return nil, fmt.Errorf("duplicate record found for tag %d", tag)
		}
		h.records[tag] = value
	}

	return h, nil
}

// validate checks that the header contains all mandatory fields and that their values are well-formed.
// This ensures the header is usable by the rest of the application.
func (h *Header) validate() error {
	// The version field is mandatory.
	if _, ok := h.records[TagVersion]; !ok {
		return fmt.Errorf("header is missing mandatory version field")
	}

	// Validate the version field. It must be a valid uint16 and not exceed the current supported version.
	if version, err := h.GetUint16(TagVersion); err != nil {
		return fmt.Errorf("invalid version field: %w", err)
	} else if version > CurrentVersion {
		return fmt.Errorf("unsupported version: %d (current: %d)", version, CurrentVersion)
	}

	// If the flags field is present, validate its format.
	if _, ok := h.records[TagFlags]; ok {
		if _, err := h.GetUint32(TagFlags); err != nil {
			return fmt.Errorf("invalid flags field: %w", err)
		}
	}

	// If the original size field is present, validate its format and value.
	if _, ok := h.records[TagOriginalSize]; ok {
		if size, err := h.GetUint64(TagOriginalSize); err != nil {
			return fmt.Errorf("invalid original size field: %w", err)
		} else if size == 0 {
			// A size of zero is invalid as we wouldn't be processing an empty file.
			return fmt.Errorf("original size cannot be zero")
		}
	}

	return nil
}