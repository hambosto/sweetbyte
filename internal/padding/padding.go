// Package padding provides PKCS#7 padding functionalities.
package padding

import (
	"bytes"
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

	// Calculate padding length (1 to blockSize)
	paddingLen := p.blockSize - (len(data) % p.blockSize)

	// Create padding bytes - all bytes have the value of padding length
	padding := bytes.Repeat([]byte{byte(paddingLen)}, paddingLen)

	return append(data, padding...), nil
}

// Unpad removes PKCS#7 padding from the data.
func (p *padding) Unpad(data []byte) ([]byte, error) {
	dataLen := len(data)

	if dataLen == 0 {
		return nil, fmt.Errorf("cannot unpad empty data")
	}

	if dataLen%p.blockSize != 0 {
		return nil, fmt.Errorf("data length %d is not a multiple of block size %d", dataLen, p.blockSize)
	}

	// Get padding length from last byte
	paddingLen := int(data[dataLen-1])

	// Validate padding length
	if paddingLen == 0 || paddingLen > p.blockSize {
		return nil, fmt.Errorf("invalid padding length %d, must be between 1 and %d", paddingLen, p.blockSize)
	}

	if paddingLen > dataLen {
		return nil, fmt.Errorf("padding length %d exceeds data length %d", paddingLen, dataLen)
	}

	// Verify all padding bytes have the correct value (constant-time)
	paddingStart := dataLen - paddingLen
	paddingBytes := data[paddingStart:]
	var invalid byte = 0
	for _, b := range paddingBytes {
		invalid |= b ^ byte(paddingLen)
	}
	if invalid != 0 {
		return nil, fmt.Errorf("invalid padding bytes")
	}

	return data[:paddingStart], nil
}
