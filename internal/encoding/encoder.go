// Package encoding provides data encoding and decoding functionality using Reed-Solomon codes.
package encoding

import (
	"fmt"

	"github.com/klauspost/reedsolomon"
)

const (
	// MaxDataLen is the maximum length of data that can be encoded.
	MaxDataLen = 1 << 30
)

// Encoder defines the interface for data encoding and decoding.
type Encoder interface {
	Encode(data []byte) ([]byte, error)
	Decode(encoded []byte) ([]byte, error)
}

// reedSolomonEncoder handles Reed-Solomon encoding and decoding.
type ReedSolomonEncoder struct {
	dataShards   int
	parityShards int
	encoder      reedsolomon.Encoder
	shards       *Shards
}

// NewEncoder creates a new Encoder with the specified number of data and parity shards.
func NewEncoder(dataShards, parityShards int) (Encoder, error) {
	// Validate the number of shards.
	if dataShards <= 0 {
		return nil, fmt.Errorf("data shards must be positive")
	}
	if parityShards <= 0 {
		return nil, fmt.Errorf("parity shards must be positive")
	}
	if dataShards+parityShards > 255 {
		return nil, fmt.Errorf("total shards cannot exceed 255")
	}

	// Create a new Reed-Solomon encoder.
	enc, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		return nil, fmt.Errorf("failed to create reed-solomon encoder: %w", err)
	}

	return &ReedSolomonEncoder{
		dataShards:   dataShards,
		parityShards: parityShards,
		encoder:      enc,
		shards:       NewShards(dataShards, parityShards),
	}, nil
}

// Encode encodes the given data using Reed-Solomon codes.
func (e *ReedSolomonEncoder) Encode(data []byte) ([]byte, error) {
	// Validate the data length.
	if len(data) == 0 {
		return nil, fmt.Errorf("input data cannot be empty")
	}
	if len(data) > MaxDataLen {
		return nil, fmt.Errorf("data size %d exceeds maximum %d bytes", len(data), MaxDataLen)
	}

	// Split the data into shards.
	shards := e.shards.Split(data)
	// Encode the shards.
	if err := e.encoder.Encode(shards); err != nil {
		return nil, fmt.Errorf("encoding failed: %w", err)
	}

	// Combine the shards into a single byte slice.
	return e.shards.Combine(shards), nil
}

// Decode decodes the given encoded data.
func (e *ReedSolomonEncoder) Decode(encoded []byte) ([]byte, error) {
	totalShards := e.dataShards + e.parityShards

	// Validate the encoded data length.
	if len(encoded) == 0 {
		return nil, fmt.Errorf("encoded data cannot be empty")
	}
	if len(encoded)%totalShards != 0 {
		return nil, fmt.Errorf("encoded data length %d not divisible by total shards %d", len(encoded), totalShards)
	}

	// Split the encoded data into shards.
	shards := e.shards.SplitEncoded(encoded)
	// Reconstruct the shards.
	if err := e.encoder.Reconstruct(shards); err != nil {
		return nil, fmt.Errorf("reconstruction failed: %w", err)
	}

	// Extract the original data from the shards.
	data, err := e.shards.Extract(shards)
	if err != nil {
		return nil, fmt.Errorf("failed to extract data from shards: %w", err)
	}

	return data, nil
}
