// Package header provides functionality for creating, reading, and writing file headers.
package header

import (
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/utils"
)

// Reader handles the process of converting a byte stream into a structured Header.
type Reader struct {
	data   []byte
	offset int
}

// NewReader creates and returns a new Reader instance.
func NewReader() *Reader {
	return &Reader{}
}

// Read deserializes a header from an io.Reader.
func Read(r io.Reader) (*Header, error) {
	reader := NewReader()
	return reader.Read(r)
}

// Read consumes bytes from an io.Reader to construct a Header.
func (r *Reader) Read(reader io.Reader) (*Header, error) {
	data := make([]byte, TotalHeaderSize)
	if _, err := io.ReadFull(reader, data); err != nil {
		return nil, fmt.Errorf("failed to read header data: %w", err)
	}
	return r.Unmarshal(data)
}

// Unmarshal parses a byte slice into a Header struct.
func (r *Reader) Unmarshal(data []byte) (*Header, error) {
	if len(data) != TotalHeaderSize {
		return nil, fmt.Errorf("invalid header size: expected %d bytes, got %d", TotalHeaderSize, len(data))
	}
	r.data = data
	r.offset = 0

	header := &Header{}
	if err := r.parseHeader(header); err != nil {
		return nil, fmt.Errorf("header parsing failed: %w", err)
	}
	return header, nil
}

func (r *Reader) parseHeader(h *Header) error {
	var data []byte
	var err error

	if data, err = r.readBytes(MagicSize); err != nil {
		return err
	}
	copy(h.magic[:], data)

	if data, err = r.readBytes(VersionSize); err != nil {
		return err
	}
	h.version = utils.FromBytes[uint16](data)

	if data, err = r.readBytes(FlagsSize); err != nil {
		return err
	}
	h.flags = utils.FromBytes[uint32](data)

	if data, err = r.readBytes(SaltSize); err != nil {
		return err
	}
	copy(h.salt[:], data)

	if data, err = r.readBytes(OriginalSizeSize); err != nil {
		return err
	}
	h.originalSize = utils.FromBytes[uint64](data)

	if data, err = r.readBytes(AuthTagSize); err != nil {
		return err
	}
	copy(h.authTag[:], data)

	if data, err = r.readBytes(PaddingSize); err != nil {
		return err
	}
	copy(h.padding[:], data)

	return nil
}

func (r *Reader) readBytes(n int) ([]byte, error) {
	if r.offset+n > len(r.data) {
		return nil, fmt.Errorf("cannot read %d bytes at offset %d: buffer length is %d", n, r.offset, len(r.data))
	}
	result := r.data[r.offset : r.offset+n]
	r.offset += n
	return result, nil
}
