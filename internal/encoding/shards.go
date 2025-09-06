// Package encoding provides Reed-Solomon encoding and decoding functionalities.
package encoding

import (
	"fmt"
)

// Shards defines the interface for splitting and combining data shards.
type Shards interface {
	// Split splits the given data into data and parity shards.
	Split(data []byte) [][]byte
	// SplitEncoded splits the encoded data into shards.
	SplitEncoded(data []byte) [][]byte
	// Combine combines the shards into a single byte slice.
	Combine(shards [][]byte) []byte
	// Extract extracts the original data from the data shards.
	Extract(shards [][]byte) ([]byte, error)
}

// shards implements the Shards interface.
type shards struct {
	dataShards   int
	parityShards int
	totalShards  int
}

// NewShards creates a new Shards instance.
func NewShards(dataShards, parityShards int) Shards {
	return &shards{
		dataShards:   dataShards,
		parityShards: parityShards,
		totalShards:  dataShards + parityShards,
	}
}

// Split splits the given data into data and parity shards.
func (s *shards) Split(data []byte) [][]byte {
	// Calculate the size of each shard.
	shardSize := (len(data) + s.dataShards - 1) / s.dataShards
	// Create the shards.
	shards := make([][]byte, s.totalShards)
	for i := range shards {
		shards[i] = make([]byte, shardSize)
	}

	// Distribute the data among the data shards.
	for i, b := range data {
		shardIndex := i / shardSize
		posInShard := i % shardSize
		shards[shardIndex][posInShard] = b
	}

	return shards
}

// SplitEncoded splits the encoded data into shards.
func (s *shards) SplitEncoded(data []byte) [][]byte {
	// Calculate the size of each shard.
	shardSize := len(data) / s.totalShards
	// Create the shards.
	shards := make([][]byte, s.totalShards)

	// Copy the data into the shards.
	for i := range shards {
		start := i * shardSize
		end := (i + 1) * shardSize
		shards[i] = make([]byte, shardSize)
		copy(shards[i], data[start:end])
	}

	return shards
}

// Combine combines the shards into a single byte slice.
func (s *shards) Combine(shards [][]byte) []byte {
	if len(shards) == 0 {
		return nil
	}

	// Get the size of each shard.
	shardSize := len(shards[0])
	// Calculate the total size of the combined data.
	totalSize := shardSize * len(shards)
	// Create a buffer for the combined data.
	result := make([]byte, totalSize)
	// Copy the data from each shard into the buffer.
	for i, shard := range shards {
		start := i * shardSize
		copy(result[start:start+shardSize], shard)
	}

	return result
}

// Extract extracts the original data from the data shards.
func (s *shards) Extract(shards [][]byte) ([]byte, error) {
	// Ensure there are enough shards to reconstruct the data.
	if len(shards) < s.dataShards {
		return nil, fmt.Errorf("insufficient shards, have %d but need at least %d data shards", len(shards), s.dataShards)
	}

	// Get the size of each shard.
	shardSize := len(shards[0])
	// Create a buffer for the combined data.
	combined := make([]byte, 0, shardSize*s.dataShards)
	// Append the data from each data shard to the buffer.
	for i := 0; i < s.dataShards; i++ {
		combined = append(combined, shards[i]...)
	}

	return combined, nil
}
