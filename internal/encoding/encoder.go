package encoding

import (
	"fmt"

	"github.com/klauspost/reedsolomon"
)

// Reed-Solomon Encoding Configuration
const (
	MaxDataLen = 1 << 30 // Maximum data length (1GB)
)

// Encoder handles Reed-Solomon encoding and decoding operations
type Encoder struct {
	dataShards   int
	parityShards int
	encoder      reedsolomon.Encoder
	shards       *Shards
}

// NewEncoder creates a new Reed-Solomon encoder with the specified number of data and parity shards
func NewEncoder(dataShards, parityShards int) (*Encoder, error) {
	if dataShards <= 0 {
		return nil, fmt.Errorf("encoder failed: data shards must be positive")
	}
	if parityShards <= 0 {
		return nil, fmt.Errorf("encoder failed: parity shards must be positive")
	}
	if dataShards+parityShards > 255 {
		return nil, fmt.Errorf("encoder failed: total shards cannot exceed 255")
	}

	enc, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		return nil, fmt.Errorf("failed to create reed-solomon encoder: %w", err)
	}

	return &Encoder{
		dataShards:   dataShards,
		parityShards: parityShards,
		encoder:      enc,
		shards:       NewShards(dataShards, parityShards),
	}, nil
}

// Encode encodes the input data using Reed-Solomon encoding
func (e *Encoder) Encode(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("encoding failed: input data cannot be empty")
	}
	if len(data) > MaxDataLen {
		return nil, fmt.Errorf("encoding failed: data size %d exceeds maximum %d bytes", len(data), MaxDataLen)
	}

	shards := e.shards.Split(data)
	if err := e.encoder.Encode(shards); err != nil {
		return nil, fmt.Errorf("encoding failed: %w", err)
	}

	return e.shards.Combine(shards), nil
}

// Decode decodes the Reed-Solomon encoded data
func (e *Encoder) Decode(encoded []byte) ([]byte, error) {
	totalShards := e.dataShards + e.parityShards

	if len(encoded) == 0 {
		return nil, fmt.Errorf("decoding failed: encoded data cannot be empty")
	}
	if len(encoded)%totalShards != 0 {
		return nil, fmt.Errorf("decoding failed: encoded data length %d not divisible by total shards %d", len(encoded), totalShards)
	}

	shards := e.shards.SplitEncoded(encoded)
	if err := e.encoder.Reconstruct(shards); err != nil {
		return nil, fmt.Errorf("reconstruction failed: %w", err)
	}

	return e.shards.Extract(shards)
}
