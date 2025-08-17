package header

import (
	"fmt"
	"io"
)

type Deserializer struct {
	data   []byte
	offset int
}

func NewDeserializer() *Deserializer {
	return &Deserializer{}
}

func (d *Deserializer) Read(r io.Reader) (*Header, error) {
	data := make([]byte, TotalHeaderSize)
	n, err := io.ReadFull(r, data)
	if err != nil {
		return nil, fmt.Errorf("failed to read header data: read %d of %d bytes: %w", n, TotalHeaderSize, err)
	}

	return d.Unmarshal(data)
}

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

	if err := d.validateParsedHeader(header); err != nil {
		return nil, fmt.Errorf("header validation failed: %w", err)
	}

	return header, nil
}

func (d *Deserializer) parseHeader(h *Header) error {
	copy(h.magic[:], d.readBytes(MagicSize))

	h.version = bytesToUint16(d.readBytes(VersionSize))
	h.flags = bytesToUint32(d.readBytes(FlagsSize))
	copy(h.salt[:], d.readBytes(SaltSize))

	h.originalSize = bytesToUint64(d.readBytes(OriginalSizeSize))
	copy(h.integrityHash[:], d.readBytes(IntegrityHashSize))
	copy(h.authTag[:], d.readBytes(AuthTagSize))

	h.checksum = bytesToUint32(d.readBytes(ChecksumSize))
	copy(h.padding[:], d.readBytes(PaddingSize))

	return nil
}

func (d *Deserializer) validateParsedHeader(h *Header) error {
	if !secureCompare(h.magic[:], []byte(MagicBytes)) {
		return fmt.Errorf("invalid magic bytes: expected %s, got %s", MagicBytes, string(h.magic[:]))
	}

	if h.version == 0 {
		return fmt.Errorf("invalid version: cannot be zero")
	}
	if h.version > CurrentVersion {
		return fmt.Errorf("unsupported version: %d (maximum supported: %d)",
			h.version, CurrentVersion)
	}

	if h.originalSize == 0 {
		return fmt.Errorf("invalid original size: cannot be zero")
	}

	zeroSalt := make([]byte, SaltSize)
	if secureCompare(h.salt[:], zeroSalt) {
		return fmt.Errorf("invalid salt: all zeros detected")
	}

	return nil
}

func (d *Deserializer) readBytes(n int) []byte {
	if d.offset+n > len(d.data) {
		result := make([]byte, n)
		return result
	}

	result := d.data[d.offset : d.offset+n]
	d.offset += n
	return result
}
