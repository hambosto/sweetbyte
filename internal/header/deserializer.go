package header

import (
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/utils"
)

// Deserializer handles deserializing headers from byte streams
type Deserializer struct {
	data      []byte
	offset    int
	validator *Validator
}

// NewDeserializer creates a new Deserializer
func NewDeserializer() *Deserializer {
	return &Deserializer{
		validator: NewValidator(),
	}
}

// Read reads a header from an io.Reader
func (d *Deserializer) Read(r io.Reader) (*Header, error) {
	data := make([]byte, TotalHeaderSize)
	n, err := io.ReadFull(r, data)
	if err != nil {
		return nil, fmt.Errorf("failed to read header data: read %d of %d bytes: %w", n, TotalHeaderSize, err)
	}

	return d.Unmarshal(data)
}

// Unmarshal unmarshals a header from a byte slice
func (d *Deserializer) Unmarshal(data []byte) (*Header, error) {
	if len(data) != TotalHeaderSize {
		return nil, fmt.Errorf("invalid header size: expected %d bytes, got %d", TotalHeaderSize, len(data))
	}

	d.data = data
	d.offset = 0

	header := &Header{}
	if err := d.parseHeader(header); err != nil {
		return nil, fmt.Errorf("header parsing failed: %w", err)
	}

	if err := d.validator.ValidateAfterDeserialization(header); err != nil {
		return nil, fmt.Errorf("header validation failed: %w", err)
	}

	return header, nil
}

func (d *Deserializer) parseHeader(h *Header) error {
	copy(h.magic[:], d.readBytes(MagicSize))
	h.version = utils.FromBytes[uint16](d.readBytes(VersionSize))
	h.flags = utils.FromBytes[uint32](d.readBytes(FlagsSize))
	copy(h.salt[:], d.readBytes(SaltSize))
	h.originalSize = utils.FromBytes[uint64](d.readBytes(OriginalSizeSize))
	copy(h.integrityHash[:], d.readBytes(IntegrityHashSize))
	copy(h.authTag[:], d.readBytes(AuthTagSize))
	h.checksum = utils.FromBytes[uint32](d.readBytes(ChecksumSize))
	copy(h.padding[:], d.readBytes(PaddingSize))
	return nil
}

func (d *Deserializer) readBytes(n int) []byte {
	if d.offset+n > len(d.data) {
		return make([]byte, n)
	}
	result := d.data[d.offset : d.offset+n]
	d.offset += n
	return result
}
