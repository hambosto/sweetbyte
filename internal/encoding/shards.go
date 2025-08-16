package encoding

import (
	"fmt"
)

// Shards manages the logic of splitting data into shards for encoding
// and combining them back after decoding.
type Shards struct {
	dataShards   int
	parityShards int
	totalShards  int
}

// NewShards creates a new shard manager.
func NewShards(dataShards, parityShards int) *Shards {
	return &Shards{
		dataShards:   dataShards,
		parityShards: parityShards,
		totalShards:  dataShards + parityShards,
	}
}

// Split divides the input data into a set of data shards.
// It calculates the appropriate shard size and distributes the data across
// the data shards, leaving the parity shards empty for the encoder to fill.
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

// SplitEncoded divides a fully encoded byte slice (data + parity) back into shards.
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

// Combine merges a set of shards into a single byte slice.
// This is used to create the final encoded output.
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

// Extract recovers the original data from a set of reconstructed shards.
// It combines only the data shards, discarding the parity shards.
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
