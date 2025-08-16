package encoding

import (
	"fmt"
)

// Shards handles the splitting and combining of data shards
type Shards struct {
	dataShards   int
	parityShards int
	totalShards  int
}

// NewShards creates a new shard handler
func NewShards(dataShards, parityShards int) *Shards {
	return &Shards{
		dataShards:   dataShards,
		parityShards: parityShards,
		totalShards:  dataShards + parityShards,
	}
}

// Split splits input data into shards for encoding
func (s *Shards) Split(data []byte) [][]byte {
	// calculates the size each shard should have
	// Ensures all data fits by rounding up division
	shardSize := (len(data) + s.dataShards - 1) / s.dataShards

	// create empty shards creates a slice of empty byte slices for all shards
	shards := make([][]byte, s.totalShards)
	for i := range shards {
		shards[i] = make([]byte, shardSize)
	}

	// Distribute data bytes across data shards
	for i, b := range data {
		shardIndex := i / shardSize
		posInShard := i % shardSize
		shards[shardIndex][posInShard] = b
	}

	return shards
}

// SplitEncoded splits encoded data back into individual shards
func (s *Shards) SplitEncoded(data []byte) [][]byte {
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

// Combine combines all shards into a single byte slice
func (s *Shards) Combine(shards [][]byte) []byte {
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

// Extract extracts the original data from the reconstructed data shards
func (s *Shards) Extract(shards [][]byte) ([]byte, error) {
	if len(shards) < s.dataShards {
		return nil, fmt.Errorf("insufficient shards, have %d but need at least %d data shards", len(shards), s.dataShards)
	}

	shardSize := len(shards[0])
	combined := make([]byte, 0, shardSize*s.dataShards)

	// Only combine data shards (first dataShards number of shards)
	for i := 0; i < s.dataShards; i++ {
		combined = append(combined, shards[i]...)
	}

	return combined, nil
}
