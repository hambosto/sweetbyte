// Package encoding provides data encoding and decoding functionality using Reed-Solomon codes.
package encoding

import (
	"fmt"
)

// Shards handles splitting and combining data shards for Reed-Solomon encoding.
type Shards struct {
	dataShards   int
	parityShards int
	totalShards  int
}

// NewShards creates a new Shards instance.
func NewShards(dataShards, parityShards int) *Shards {
	return &Shards{
		dataShards:   dataShards,
		parityShards: parityShards,
		totalShards:  dataShards + parityShards,
	}
}

// Split splits the data into shards.
func (s *Shards) Split(data []byte) [][]byte {
	// Calculate the size of each shard.
	shardSize := (len(data) + s.dataShards - 1) / s.dataShards

	// Create the shards.
	shards := make([][]byte, s.totalShards)
	for i := range shards {
		shards[i] = make([]byte, shardSize)
	}

	// Distribute the data among the shards.
	for i, b := range data {
		shardIndex := i / shardSize
		posInShard := i % shardSize
		shards[shardIndex][posInShard] = b
	}

	return shards
}

// SplitEncoded splits the encoded data into shards.
func (s *Shards) SplitEncoded(data []byte) [][]byte {
	// Calculate the size of each shard.
	shardSize := len(data) / s.totalShards
	shards := make([][]byte, s.totalShards)

	// Create the shards from the encoded data.
	for i := range shards {
		start := i * shardSize
		end := (i + 1) * shardSize
		shards[i] = make([]byte, shardSize)
		copy(shards[i], data[start:end])
	}

	return shards
}

// Combine combines the shards into a single byte slice.
func (s *Shards) Combine(shards [][]byte) []byte {
	if len(shards) == 0 {
		return nil
	}

	// Calculate the total size of the combined data.
	shardSize := len(shards[0])
	totalSize := shardSize * len(shards)
	result := make([]byte, totalSize)

	// Copy the data from each shard into the result.
	for i, shard := range shards {
		start := i * shardSize
		copy(result[start:start+shardSize], shard)
	}

	return result
}

// Extract extracts the original data from the shards.
func (s *Shards) Extract(shards [][]byte) ([]byte, error) {
	// Check if there are enough shards to reconstruct the data.
	if len(shards) < s.dataShards {
		return nil, fmt.Errorf("insufficient shards, have %d but need at least %d data shards", len(shards), s.dataShards)
	}

	// Combine the data shards to get the original data.
	shardSize := len(shards[0])
	combined := make([]byte, 0, shardSize*s.dataShards)

	for i := 0; i < s.dataShards; i++ {
		combined = append(combined, shards[i]...)
	}

	return combined, nil
}
