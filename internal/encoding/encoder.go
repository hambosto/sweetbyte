package encoding

import (
	"fmt"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/errors"
	"github.com/klauspost/reedsolomon"
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
		return nil, fmt.Errorf("%w: data shards must be positive", errors.ErrEncodingFailed)
	}
	if parityShards <= 0 {
		return nil, fmt.Errorf("%w: parity shards must be positive", errors.ErrEncodingFailed)
	}
	if dataShards+parityShards > 255 {
		return nil, fmt.Errorf("%w: total shards cannot exceed 255", errors.ErrEncodingFailed)
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
		return nil, fmt.Errorf("%w: input data cannot be empty", errors.ErrEncodingFailed)
	}
	if len(data) > config.MaxDataLen {
		return nil, fmt.Errorf("%w: data size %d exceeds maximum %d bytes",
			errors.ErrEncodingFailed, len(data), config.MaxDataLen)
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
		return nil, fmt.Errorf("%w: encoded data cannot be empty", errors.ErrDecodingFailed)
	}
	if len(encoded)%totalShards != 0 {
		return nil, fmt.Errorf("%w: encoded data length %d not divisible by total shards %d",
			errors.ErrDecodingFailed, len(encoded), totalShards)
	}

	shards := e.shards.SplitEncoded(encoded)
	if err := e.encoder.Reconstruct(shards); err != nil {
		return nil, fmt.Errorf("reconstruction failed: %w", err)
	}

	return e.shards.Extract(shards)
}

// DataShards returns the number of data shards
func (e *Encoder) DataShards() int {
	return e.dataShards
}

// ParityShards returns the number of parity shards
func (e *Encoder) ParityShards() int {
	return e.parityShards
}

// TotalShards returns the total number of shards
func (e *Encoder) TotalShards() int {
	return e.dataShards + e.parityShards
}
