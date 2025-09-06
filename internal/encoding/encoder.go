package encoding

import (
	"fmt"

	"github.com/klauspost/reedsolomon"
)

const (
	MaxDataLen = 1 << 30
)

type Encoder interface {
	Encode(data []byte) ([]byte, error)
	Decode(encoded []byte) ([]byte, error)
}

type encoder struct {
	dataShards   int
	parityShards int
	encoder      reedsolomon.Encoder
	shards       Shards
}

func NewEncoder(dataShards, parityShards int) (Encoder, error) {
	if dataShards <= 0 {
		return nil, fmt.Errorf("data shards must be positive")
	}
	if parityShards <= 0 {
		return nil, fmt.Errorf("parity shards must be positive")
	}
	if dataShards+parityShards > 255 {
		return nil, fmt.Errorf("total shards cannot exceed 255")
	}

	enc, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		return nil, fmt.Errorf("failed to create reed-solomon encoder: %w", err)
	}

	return &encoder{
		dataShards:   dataShards,
		parityShards: parityShards,
		encoder:      enc,
		shards:       NewShards(dataShards, parityShards),
	}, nil
}

func (e *encoder) Encode(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("input data cannot be empty")
	}
	if len(data) > MaxDataLen {
		return nil, fmt.Errorf("data size %d exceeds maximum %d bytes", len(data), MaxDataLen)
	}

	shards := e.shards.Split(data)
	if err := e.encoder.Encode(shards); err != nil {
		return nil, fmt.Errorf("encoding failed: %w", err)
	}

	return e.shards.Combine(shards), nil
}

func (e *encoder) Decode(encoded []byte) ([]byte, error) {
	totalShards := e.dataShards + e.parityShards
	if len(encoded) == 0 {
		return nil, fmt.Errorf("encoded data cannot be empty")
	}
	if len(encoded)%totalShards != 0 {
		return nil, fmt.Errorf("encoded data length %d not divisible by total shards %d", len(encoded), totalShards)
	}

	shards := e.shards.SplitEncoded(encoded)
	if err := e.encoder.Reconstruct(shards); err != nil {
		return nil, fmt.Errorf("reconstruction failed: %w", err)
	}

	data, err := e.shards.Extract(shards)
	if err != nil {
		return nil, fmt.Errorf("failed to extract data from shards: %w", err)
	}

	return data, nil
}
