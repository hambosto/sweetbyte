// Package padding provides an implementation of PKCS7 padding for cryptographic operations.
// This scheme ensures that plaintext data is always a multiple of a specified block size,
// which is often a requirement for block ciphers.
package padding

import (
	"fmt"
)

// Padding represents a PKCS7 padding scheme with a defined block size.
type Padding struct {
	blockSize int // The block size to which data will be padded (e.g., 16 for AES).
}

// NewPadding creates and returns a new Padding instance.
// It validates the provided blockSize, ensuring it is within a valid range.
func NewPadding(blockSize int) (*Padding, error) {
	if blockSize <= 0 || blockSize > 255 { // PKCS7 padding values are bytes, so block size cannot exceed 255.
		return nil, fmt.Errorf("block size must be between 1 and 255, got %d", blockSize) // Return error for invalid block size.
	}

	return &Padding{
		blockSize: blockSize, // Assign the validated block size.
	}, nil
}

// Pad applies PKCS7 padding to the input data.
// It calculates the number of padding bytes needed to make the data a multiple of blockSize,
// creates a padding slice, and appends it to the original data.
func (p *Padding) Pad(data []byte) ([]byte, error) {
	if data == nil { // Ensure input data is not nil.
		return nil, fmt.Errorf("data cannot be nil") // Return error for nil data.
	}

	padding := p.blockSize - (len(data) % p.blockSize) // Calculate the number of padding bytes needed.
	padText := make([]byte, padding)                   // Create a new byte slice for the padding.

	for i := range padText { // Fill the padding slice with the padding value.
		padText[i] = byte(padding)
	}

	return append(data, padText...), nil // Append the padding to the original data and return.
}

// Unpad removes PKCS7 padding from the input data.
// It validates the data length against the block size, extracts the padding value,
// and verifies the padding bytes before returning the original unpadded data.
func (p *Padding) Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 { // Ensure input data is not empty.
		return nil, fmt.Errorf("data cannot be empty") // Return error for empty data.
	}

	if len(data)%p.blockSize != 0 { // Check if the data length is a multiple of the block size.
		return nil, fmt.Errorf("data length must be multiple of block size %d, got %d", p.blockSize, len(data)) // Return error if not a multiple.
	}

	padding := int(data[len(data)-1])          // The last byte of PKCS7 padding indicates the padding length.
	if padding == 0 || padding > p.blockSize { // Validate the padding value.
		return nil, fmt.Errorf("padding value must be between 1 and %d, got %d", p.blockSize, padding) // Return error for invalid padding value.
	}

	if padding > len(data) { // Ensure padding value does not exceed data length.
		return nil, fmt.Errorf("padding value %d exceeds data length %d", padding, len(data)) // Return error if padding is too large.
	}

	for i := len(data) - padding; i < len(data); i++ { // Verify that all padding bytes have the correct value.
		if data[i] != byte(padding) { // If any padding byte is incorrect, data is malformed or tampered.
			return nil, fmt.Errorf("invalid padding byte at position %d, expected %d got %d", i, padding, data[i]) // Return error for invalid padding.
		}
	}

	return data[:len(data)-padding], nil // Return the original data slice, excluding the padding bytes.
}
