package encoding

import (
	"fmt"
)

type Shards interface {
	Split(data []byte) [][]byte
	SplitEncoded(data []byte) [][]byte
	Combine(shards [][]byte) []byte
	Extract(shards [][]byte) ([]byte, error)
}

type shards struct {
	dataShards   int
	parityShards int
	totalShards  int
}

func NewShards(dataShards, parityShards int) *shards {
	return &shards{
		dataShards:   dataShards,
		parityShards: parityShards,
		totalShards:  dataShards + parityShards,
	}
}

func (s *shards) Split(data []byte) [][]byte {
	shardSize := (len(data) + s.dataShards - 1) / s.dataShards
	shards := make([][]byte, s.totalShards)
	for i := range shards {
		shards[i] = make([]byte, shardSize)
	}

	for i, b := range data {
		shardIndex := i / shardSize
		posInShard := i % shardSize
		shards[shardIndex][posInShard] = b
	}

	return shards
}

func (s *shards) SplitEncoded(data []byte) [][]byte {
	shardSize := len(data) / s.totalShards
	shards := make([][]byte, s.totalShards)

	for i := range shards {
		start := i * shardSize
		end := (i + 1) * shardSize
		shards[i] = make([]byte, shardSize)
		copy(shards[i], data[start:end])
	}

	return shards
}

func (s *shards) Combine(shards [][]byte) []byte {
	if len(shards) == 0 {
		return nil
	}

	shardSize := len(shards[0])
	totalSize := shardSize * len(shards)
	result := make([]byte, totalSize)
	for i, shard := range shards {
		start := i * shardSize
		copy(result[start:start+shardSize], shard)
	}

	return result
}

func (s *shards) Extract(shards [][]byte) ([]byte, error) {
	if len(shards) < s.dataShards {
		return nil, fmt.Errorf("insufficient shards, have %d but need at least %d data shards", len(shards), s.dataShards)
	}

	shardSize := len(shards[0])
	combined := make([]byte, 0, shardSize*s.dataShards)
	for i := 0; i < s.dataShards; i++ {
		combined = append(combined, shards[i]...)
	}

	return combined, nil
}
