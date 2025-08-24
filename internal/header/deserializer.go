// Package header provides functionality for creating, reading, and writing file headers.
package header

import (
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/utils"
)

// Deserializer handles the process of converting a byte stream into a structured Header.
// It includes validation to ensure the header is well-formed and conforms to expected values.
type Deserializer struct {
	data      []byte     // The raw byte slice containing the header data.
	offset    int        // The current reading offset within the data slice.
	validator *Validator // A validator to check the header's integrity after parsing.
}

// NewDeserializer creates and returns a new Deserializer instance.
// It initializes the necessary components, including the validator.
func NewDeserializer() *Deserializer {
	return &Deserializer{
		validator: NewValidator(),
	}
}

// Read consumes bytes from an io.Reader to construct a Header.
// It reads the exact number of bytes required for a full header and then unmarshals them.
// Returns an error if reading from the reader fails or is incomplete.
func (d *Deserializer) Read(r io.Reader) (*Header, error) {
	// Allocate a buffer of the precise size for the header.
	data := make([]byte, TotalHeaderSize)
	// Read the full header data from the input stream.
	n, err := io.ReadFull(r, data)
	if err != nil {
		return nil, fmt.Errorf("failed to read header data: read %d of %d bytes: %w", n, TotalHeaderSize, err)
	}

	// Unmarshal the byte data into a Header struct.
	return d.Unmarshal(data)
}

// Unmarshal parses a byte slice into a Header struct.
// It performs a size check, parses the fields, and then validates the parsed header.
// Returns an error if the data size is incorrect, parsing fails, or validation fails.
func (d *Deserializer) Unmarshal(data []byte) (*Header, error) {
	// Ensure the provided data is of the correct size for a header.
	if len(data) != TotalHeaderSize {
		return nil, fmt.Errorf("invalid header size: expected %d bytes, got %d", TotalHeaderSize, len(data))
	}

	// Reset the deserializer's state for the new data.
	d.data = data
	d.offset = 0

	// Parse the byte data into the header fields.
	header := &Header{}
	if err := d.parseHeader(header); err != nil {
		return nil, fmt.Errorf("header parsing failed: %w", err)
	}

	// Validate the header's contents after deserialization.
	if err := d.validator.ValidateAfterDeserialization(header); err != nil {
		return nil, fmt.Errorf("header validation failed: %w", err)
	}

	return header, nil
}

// parseHeader extracts data from the byte slice and populates the fields of the Header struct.
// It reads the header fields in the order they are defined in the specification.
func (d *Deserializer) parseHeader(h *Header) error {
	var data []byte
	var err error

	// Read the magic bytes, which identify the file type.
	if data, err = d.readBytes(MagicSize); err != nil {
		return fmt.Errorf("failed to read magic bytes: %w", err)
	}
	copy(h.magic[:], data)

	// Read the version of the header format.
	if data, err = d.readBytes(VersionSize); err != nil {
		return fmt.Errorf("failed to read version: %w", err)
	}
	h.version = utils.FromBytes[uint16](data)

	// Read the flags that control encryption and compression options.
	if data, err = d.readBytes(FlagsSize); err != nil {
		return fmt.Errorf("failed to read flags: %w", err)
	}
	h.flags = utils.FromBytes[uint32](data)

	// Read the salt used in the key derivation process.
	if data, err = d.readBytes(SaltSize); err != nil {
		return fmt.Errorf("failed to read salt: %w", err)
	}
	copy(h.salt[:], data)

	// Read the original size of the file before any processing.
	if data, err = d.readBytes(OriginalSizeSize); err != nil {
		return fmt.Errorf("failed to read original size: %w", err)
	}
	h.originalSize = utils.FromBytes[uint64](data)

	// Read the integrity hash of the header's structural components.
	if data, err = d.readBytes(IntegrityHashSize); err != nil {
		return fmt.Errorf("failed to read integrity hash: %w", err)
	}
	copy(h.integrityHash[:], data)

	// Read the authentication tag to verify the header's authenticity.
	if data, err = d.readBytes(AuthTagSize); err != nil {
		return fmt.Errorf("failed to read auth tag: %w", err)
	}
	copy(h.authTag[:], data)

	// Read the checksum of the entire header for a quick integrity check.
	if data, err = d.readBytes(ChecksumSize); err != nil {
		return fmt.Errorf("failed to read checksum: %w", err)
	}
	h.checksum = utils.FromBytes[uint32](data)

	// Read the random padding to obscure the header size.
	if data, err = d.readBytes(PaddingSize); err != nil {
		return fmt.Errorf("failed to read padding: %w", err)
	}
	copy(h.padding[:], data)

	return nil
}

// readBytes reads a specified number of bytes from the internal data slice and advances the offset.
// It returns an error if the read goes out of bounds, preventing silent failures.
func (d *Deserializer) readBytes(n int) ([]byte, error) {
	// Ensure the read is within the bounds of the data slice.
	if d.offset+n > len(d.data) {
		return nil, fmt.Errorf("cannot read %d bytes at offset %d: buffer length is %d", n, d.offset, len(d.data))
	}
	// Extract the slice and advance the internal offset.
	result := d.data[d.offset : d.offset+n]
	d.offset += n
	return result, nil
}
