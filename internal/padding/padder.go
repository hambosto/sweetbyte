package padding

import (
	"github.com/hambosto/sweetbyte/internal/errors"
)

// Padder handles PKCS7 padding and unpadding operations
type Padder struct {
	blockSize int
}

// NewPadder creates a new padder with the specified block size
func NewPadder(blockSize int) (*Padder, error) {
	if blockSize <= 0 || blockSize > 255 {
		return nil, errors.ErrPaddingFailed
	}

	return &Padder{
		blockSize: blockSize,
	}, nil
}

// Pad applies PKCS7 padding to the input data
func (p *Padder) Pad(data []byte) ([]byte, error) {
	if data == nil {
		return nil, errors.ErrPaddingFailed
	}

	padding := p.blockSize - (len(data) % p.blockSize)
	padText := make([]byte, padding)

	for i := range padText {
		padText[i] = byte(padding)
	}

	return append(data, padText...), nil
}

// Unpad removes PKCS7 padding from the input data
func (p *Padder) Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.ErrUnpaddingFailed
	}

	if len(data)%p.blockSize != 0 {
		return nil, errors.ErrUnpaddingFailed
	}

	padding := int(data[len(data)-1])

	if padding == 0 || padding > p.blockSize {
		return nil, errors.ErrUnpaddingFailed
	}

	if padding > len(data) {
		return nil, errors.ErrUnpaddingFailed
	}

	// Verify padding bytes
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, errors.ErrUnpaddingFailed
		}
	}

	return data[:len(data)-padding], nil
}
