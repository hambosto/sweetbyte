// Package padding provides PKCS#7 padding functionalities.
package padding

import (
	"fmt"
)

// Padding defines the interface for padding and unpadding data.
type Padding interface {
	// Pad adds PKCS#7 padding to the data.
	Pad(data []byte) ([]byte, error)
	// Unpad removes PKCS#7 padding from the data.
	Unpad(data []byte) ([]byte, error)
}

// padding implements the Padding interface.
type padding struct {
	blockSize int
}

// NewPadding creates a new Padding instance with the given block size.
func NewPadding(blockSize int) (Padding, error) {
	// Ensure the block size is valid.
	if blockSize <= 0 || blockSize > 255 {
		return nil, fmt.Errorf("block size must be between 1 and 255, got %d", blockSize)
	}
	return &padding{
		blockSize: blockSize,
	}, nil
}

// Pad adds PKCS#7 padding to the data.
func (p *padding) Pad(data []byte) ([]byte, error) {
	// Ensure the data is not nil.
	if data == nil {
		return nil, fmt.Errorf("data cannot be nil")
	}

	// Calculate the number of bytes to pad.
	padding := p.blockSize - (len(data) % p.blockSize)
	// Create the padding text.
	padText := make([]byte, padding)
	for i := range padText {
		padText[i] = byte(padding)
	}

	// Append the padding text to the data.
	return append(data, padText...), nil
}

// Unpad removes PKCS#7 padding from the data.
func (p *padding) Unpad(data []byte) ([]byte, error) {
	// Ensure the data is not empty.
	if len(data) == 0 {
		return nil, fmt.Errorf("data cannot be empty")
	}

	// Ensure the data length is a multiple of the block size.
	if len(data)%p.blockSize != 0 {
		return nil, fmt.Errorf("data length must be multiple of block size %d, got %d", p.blockSize, len(data))
	}

	// Get the padding length from the last byte.
	padding := int(data[len(data)-1])
	// Ensure the padding length is valid.
	if padding == 0 || padding > p.blockSize {
		return nil, fmt.Errorf("padding value must be between 1 and %d, got %d", p.blockSize, padding)
	}

	if padding > len(data) {
		return nil, fmt.Errorf("padding value %d exceeds data length %d", padding, len(data))
	}

	// Verify the padding bytes.
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, fmt.Errorf("invalid padding byte at position %d, expected %d got %d", i, padding, data[i])
		}
	}

	// Return the unpadded data.
	return data[:len(data)-padding], nil
}
