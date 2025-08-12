package header

import (
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/errors"
)

// Deserializer handles header deserialization
type Deserializer struct{}

// NewDeserializer creates a new header deserializer
func NewDeserializer() *Deserializer {
	return &Deserializer{}
}

// ReadFrom reads and parses a header from the reader
func (d *Deserializer) ReadHeaderFrom(r io.Reader) (*Header, error) {
	data := make([]byte, config.TotalHeaderSize)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, fmt.Errorf("%w: %v", errors.ErrIncompleteRead, err)
	}
	return d.unmarshal(data)
}

// unmarshal deserializes header from bytes
func (d *Deserializer) unmarshal(data []byte) (*Header, error) {
	if len(data) != config.TotalHeaderSize {
		return nil, fmt.Errorf("invalid header size: expected %d bytes, got %d",
			config.TotalHeaderSize, len(data))
	}

	parser := NewParser(data)
	return parser.Parse()
}
