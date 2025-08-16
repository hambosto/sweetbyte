package header

import (
	"fmt"
	"io"
)

// Deserializer handles header deserialization from binary format
type Deserializer struct {
	data   []byte
	offset int
}

// NewDeserializer creates a new deserializer instance
func NewDeserializer() *Deserializer {
	return &Deserializer{}
}

// Read reads and parses a header from the reader
func (d *Deserializer) Read(r io.Reader) (*Header, error) {
	// Read exact header size
	data := make([]byte, TotalHeaderSize)
	n, err := io.ReadFull(r, data)
	if err != nil {
		return nil, fmt.Errorf("failed to read header data: read %d of %d bytes: %w", n, TotalHeaderSize, err)
	}

	return d.Unmarshal(data)
}

// Unmarshal deserializes header from bytes
func (d *Deserializer) Unmarshal(data []byte) (*Header, error) {
	if len(data) != TotalHeaderSize {
		return nil, fmt.Errorf("invalid header size: expected %d bytes, got %d", TotalHeaderSize, len(data))
	}

	d.data = data
	d.offset = 0

	header := &Header{}

	// Parse fields in exact order
	if err := d.parseHeader(header); err != nil {
		return nil, fmt.Errorf("header parsing failed: %w", err)
	}

	// Perform basic validation
	if err := d.validateParsedHeader(header); err != nil {
		return nil, fmt.Errorf("header validation failed: %w", err)
	}

	return header, nil
}

// parseHeader extracts all fields from binary data
func (d *Deserializer) parseHeader(h *Header) error {
	// Magic bytes (4 bytes)
	copy(h.magic[:], d.readBytes(MagicSize))

	// Version (2 bytes)
	h.version = bytesToUint16(d.readBytes(VersionSize))

	// Flags (4 bytes)
	h.flags = bytesToUint32(d.readBytes(FlagsSize))

	// Salt (32 bytes)
	copy(h.salt[:], d.readBytes(SaltSize))

	// Original size (8 bytes)
	h.originalSize = bytesToUint64(d.readBytes(OriginalSizeSize))

	// Integrity hash (32 bytes)
	copy(h.integrityHash[:], d.readBytes(IntegrityHashSize))

	// Auth tag (32 bytes)
	copy(h.authTag[:], d.readBytes(AuthTagSize))

	// Checksum (4 bytes)
	h.checksum = bytesToUint32(d.readBytes(ChecksumSize))

	// Padding (16 bytes)
	copy(h.padding[:], d.readBytes(PaddingSize))

	return nil
}

// validateParsedHeader performs basic validation on parsed data
func (d *Deserializer) validateParsedHeader(h *Header) error {
	// Check magic bytes
	if !secureCompare(h.magic[:], []byte(MagicBytes)) {
		return fmt.Errorf("invalid magic bytes: expected %s, got %s", MagicBytes, string(h.magic[:]))
	}

	// Check version
	if h.version == 0 {
		return fmt.Errorf("invalid version: cannot be zero")
	}
	if h.version > CurrentVersion {
		return fmt.Errorf("unsupported version: %d (maximum supported: %d)",
			h.version, CurrentVersion)
	}

	// Check original size
	if h.originalSize == 0 {
		return fmt.Errorf("invalid original size: cannot be zero")
	}

	// Check for suspicious all-zero patterns
	zeroSalt := make([]byte, SaltSize)
	if secureCompare(h.salt[:], zeroSalt) {
		return fmt.Errorf("invalid salt: all zeros detected")
	}

	return nil
}

// readBytes reads n bytes from current offset and advances the offset
func (d *Deserializer) readBytes(n int) []byte {
	if d.offset+n > len(d.data) {
		// Return zeros if we're trying to read past the end
		// This should never happen with proper length validation
		result := make([]byte, n)
		return result
	}

	result := d.data[d.offset : d.offset+n]
	d.offset += n
	return result
}
