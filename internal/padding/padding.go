package padding

import (
	"fmt"
)

// Padding handles PKCS7 padding and unpadding operations
type Padding struct {
	blockSize int
}

// NewPadding creates a new Padding with the specified block size
func NewPadding(blockSize int) (*Padding, error) {
	if blockSize <= 0 || blockSize > 255 {
		return nil, fmt.Errorf("padding failed: invalid block size %d, must be between 1 and 255", blockSize)
	}

	return &Padding{
		blockSize: blockSize,
	}, nil
}

// Pad applies Padding padding to the input data
func (p *Padding) Pad(data []byte) ([]byte, error) {
	if data == nil {
		return nil, fmt.Errorf("padding failed: data is nil")
	}

	padding := p.blockSize - (len(data) % p.blockSize)
	padText := make([]byte, padding)

	for i := range padText {
		padText[i] = byte(padding)
	}

	return append(data, padText...), nil
}

// Unpad removes Padding padding from the input data
func (p *Padding) Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("unpadding failed: empty data")
	}

	if len(data)%p.blockSize != 0 {
		return nil, fmt.Errorf("unpadding failed: data length %d is not multiple of block size %d", len(data), p.blockSize)
	}

	padding := int(data[len(data)-1])

	if padding == 0 || padding > p.blockSize {
		return nil, fmt.Errorf("unpadding failed: invalid padding value %d, must be between 1 and %d", padding, p.blockSize)
	}

	if padding > len(data) {
		return nil, fmt.Errorf("unpadding failed: padding value %d exceeds data length %d", padding, len(data))
	}

	// Verify padding bytes
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, fmt.Errorf("unpadding failed: invalid padding byte at position %d, expected %d got %d", i, padding, data[i])
		}
	}

	return data[:len(data)-padding], nil
}
