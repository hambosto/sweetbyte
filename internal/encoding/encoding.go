package encoding

import (
	"errors"
	"fmt"

	"github.com/klauspost/reedsolomon"
)

const (
	DataShards   = 4
	ParityShards = 10
)

type Encoding struct {
	encoder      reedsolomon.Encoder
	dataShards   int
	parityShards int
}

func NewEncoding(dataShards, parityShards int) (*Encoding, error) {
	encoder, err := reedsolomon.New(dataShards, parityShards)
	if err != nil {
		return nil, err
	}

	return &Encoding{
		encoder:      encoder,
		dataShards:   dataShards,
		parityShards: parityShards,
	}, nil
}

func (e *Encoding) Encode(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.New("empty input")
	}

	shardSize := (len(data) + e.dataShards - 1) / e.dataShards
	totalShards := e.dataShards + e.parityShards

	shards := make([][]byte, totalShards)

	for i := 0; i < e.dataShards; i++ {
		shards[i] = make([]byte, shardSize)

		start := i * shardSize
		end := min(start+shardSize, len(data))

		if start < len(data) {
			copy(shards[i], data[start:end])
		}
	}

	for i := e.dataShards; i < totalShards; i++ {
		shards[i] = make([]byte, shardSize)
	}

	if err := e.encoder.Encode(shards); err != nil {
		return nil, err
	}

	result := make([]byte, 0, shardSize*totalShards)
	for _, shard := range shards {
		result = append(result, shard...)
	}

	return result, nil
}

func (e *Encoding) Decode(encoded []byte) ([]byte, error) {
	if len(encoded) == 0 {
		return nil, errors.New("empty encoded data")
	}

	totalShards := e.dataShards + e.parityShards

	if len(encoded)%totalShards != 0 {
		return nil, fmt.Errorf("invalid encoded length: %d not divisible by shards (%d)", len(encoded), totalShards)
	}

	shardSize := len(encoded) / totalShards

	shards := make([][]byte, totalShards)
	for i := range totalShards {
		start := i * shardSize
		end := start + shardSize
		shards[i] = make([]byte, shardSize)
		copy(shards[i], encoded[start:end])
	}

	if err := e.encoder.Reconstruct(shards); err != nil {
		return nil, err
	}

	result := make([]byte, 0, e.dataShards*shardSize)
	for i := 0; i < e.dataShards; i++ {
		result = append(result, shards[i]...)
	}

	return result, nil
}
