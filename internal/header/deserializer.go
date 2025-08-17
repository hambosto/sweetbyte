// Package header manages the secure header of SweetByte encrypted files.
// It defines the header structure, provides mechanisms for its creation, serialization,
// deserialization, and crucial verification processes to ensure data integrity and authenticity.
package header

import (
	"fmt"
	"io"
)

// Deserializer is responsible for parsing a byte slice or an io.Reader stream
// into a Header struct. It handles the extraction of individual header fields
// and performs initial validation checks on the parsed data.
type Deserializer struct {
	data   []byte // The raw byte data of the header to be deserialized.
	offset int    // Current reading offset within the data slice.
}

// NewDeserializer creates and returns a new Deserializer instance.
// It initializes an empty deserializer, which will be populated with data upon reading.
func NewDeserializer() *Deserializer {
	return &Deserializer{} // Return an empty struct as its state is set during `Unmarshal` or `Read`.
}

// Read reads the entire header from the provided io.Reader into a byte slice
// and then attempts to unmarshal it into a Header struct.
func (d *Deserializer) Read(r io.Reader) (*Header, error) {
	data := make([]byte, TotalHeaderSize) // Create a buffer to read the entire header.
	n, err := io.ReadFull(r, data)        // Read exactly TotalHeaderSize bytes from the reader.
	if err != nil {                       // Handle errors during reading, including EOF if not enough bytes are available.
		return nil, fmt.Errorf("failed to read header data: read %d of %d bytes: %w", n, TotalHeaderSize, err)
	}

	return d.Unmarshal(data) // Unmarshal the read bytes into a Header struct.
}

// Unmarshal parses a raw byte slice containing header data into a Header struct.
// It validates the size of the input data and then sequentially extracts each field,
// followed by a validation of the parsed header's content.
func (d *Deserializer) Unmarshal(data []byte) (*Header, error) {
	if len(data) != TotalHeaderSize { // Validate that the input data slice has the expected header size.
		return nil, fmt.Errorf("invalid header size: expected %d bytes, got %d", TotalHeaderSize, len(data))
	}

	d.data = data // Store the input data for internal processing.
	d.offset = 0  // Reset the reading offset to the beginning of the data.

	header := &Header{}                           // Create a new Header struct to populate.
	if err := d.parseHeader(header); err != nil { // Parse individual fields into the header struct.
		return nil, fmt.Errorf("header parsing failed: %w", err) // Return error if parsing fails.
	}

	if err := d.validateParsedHeader(header); err != nil { // Validate the content of the parsed header.
		return nil, fmt.Errorf("header validation failed: %w", err) // Return error if validation fails.
	}

	return header, nil // Return the successfully unmarshaled and validated header.
}

// parseHeader extracts individual fields from the internal data slice and populates the Header struct.
// It advances the internal offset after reading each field.
func (d *Deserializer) parseHeader(h *Header) error {
	copy(h.magic[:], d.readBytes(MagicSize)) // Read and copy magic bytes.

	h.version = bytesToUint16(d.readBytes(VersionSize)) // Read and convert version bytes to uint16.
	h.flags = bytesToUint32(d.readBytes(FlagsSize))     // Read and convert flags bytes to uint32.
	copy(h.salt[:], d.readBytes(SaltSize))              // Read and copy salt bytes.

	h.originalSize = bytesToUint64(d.readBytes(OriginalSizeSize)) // Read and convert original size bytes to uint64.
	copy(h.integrityHash[:], d.readBytes(IntegrityHashSize))      // Read and copy integrity hash bytes.
	copy(h.authTag[:], d.readBytes(AuthTagSize))                  // Read and copy authentication tag bytes.

	h.checksum = bytesToUint32(d.readBytes(ChecksumSize)) // Read and convert checksum bytes to uint32.
	copy(h.padding[:], d.readBytes(PaddingSize))          // Read and copy padding bytes.

	return nil // Return nil if all fields are successfully parsed.
}

// validateParsedHeader performs basic semantic validation on the fields of a newly parsed Header.
// It checks for correct magic bytes, non-zero version and original size, and non-zero salt.
func (d *Deserializer) validateParsedHeader(h *Header) error {
	if !secureCompare(h.magic[:], []byte(MagicBytes)) { // Error for incorrect magic bytes.
		return fmt.Errorf("invalid magic bytes: expected %s, got %s", MagicBytes, string(h.magic[:]))
	}

	// Check if the version is zero (invalid) or an unsupported future version.
	if h.version == 0 {
		return fmt.Errorf("invalid version: cannot be zero") // Error for zero version.
	}

	// Check if the header version is higher than the supported current version.
	if h.version > CurrentVersion {
		return fmt.Errorf("unsupported version: %d (maximum supported: %d)", h.version, CurrentVersion) // Error for unsupported version.
	}

	// Ensure the original size is not zero, as a zero-sized file is invalid in this context.
	if h.originalSize == 0 {
		return fmt.Errorf("invalid original size: cannot be zero") // Error for zero original size.
	}

	// Check if the salt is all zeros, which indicates a potential security issue.
	zeroSalt := make([]byte, SaltSize)
	if secureCompare(h.salt[:], zeroSalt) {
		return fmt.Errorf("invalid salt: all zeros detected") // Error for all-zero salt.
	}

	return nil // Return nil if all validations pass.
}

// readBytes extracts a slice of `n` bytes from the internal data slice at the current offset
// and advances the offset by `n`. It handles cases where reading goes beyond data bounds.
func (d *Deserializer) readBytes(n int) []byte {
	if d.offset+n > len(d.data) { // Check if the read would exceed the data slice bounds.
		result := make([]byte, n) // If so, return a zero-filled slice of the requested size.
		return result
	}
	result := d.data[d.offset : d.offset+n] // Extract the requested slice.
	d.offset += n                           // Advance the offset.
	return result                           // Return the extracted slice.
}
