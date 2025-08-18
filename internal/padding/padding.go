// Package padding provides PKCS#7 padding functionality.
package padding

import (
	"fmt"
)

// Padding handles PKCS#7 padding.
type Padding struct {
	blockSize int
}

// NewPadding creates a new Padding instance with the given block size.
func NewPadding(blockSize int) (*Padding, error) {
	// The block size must be between 1 and 255.
	if blockSize <= 0 || blockSize > 255 {
		return nil, fmt.Errorf("block size must be between 1 and 255, got %d", blockSize)
	}
	return &Padding{
		blockSize: blockSize,
	}, nil
}

// Pad adds PKCS#7 padding to the data.
func (p *Padding) Pad(data []byte) ([]byte, error) {
	// Data cannot be nil.
	if data == nil {
		return nil, fmt.Errorf("data cannot be nil")
	}

	// Calculate the number of bytes to pad.
	padding := p.blockSize - (len(data) % p.blockSize)
	// Create the padding text.
	padText := make([]byte, padding)

	// Fill the padding text with the padding value.
	for i := range padText {
		padText[i] = byte(padding)
	}

	// Append the padding text to the data.
	return append(data, padText...), nil
}

// Unpad removes PKCS#7 padding from the data.
func (p *Padding) Unpad(data []byte) ([]byte, error) {
	// Data cannot be empty.
	if len(data) == 0 {
		return nil, fmt.Errorf("data cannot be empty")
	}

	// The data length must be a multiple of the block size.
	if len(data)%p.blockSize != 0 {
		return nil, fmt.Errorf("data length must be multiple of block size %d, got %d", p.blockSize, len(data))
	}

	// Get the padding value from the last byte.
	padding := int(data[len(data)-1])
	// The padding value must be valid.
	if padding == 0 || padding > p.blockSize {
		return nil, fmt.Errorf("padding value must be between 1 and %d, got %d", p.blockSize, padding)
	}

	// The padding value cannot be greater than the data length.
	if padding > len(data) {
		return nil, fmt.Errorf("padding value %d exceeds data length %d", padding, len(data))
	}

	// Check if the padding bytes are valid.
	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, fmt.Errorf("invalid padding byte at position %d, expected %d got %d", i, padding, data[i])
		}
	}

	// Return the data without the padding.
	return data[:len(data)-padding], nil
}
