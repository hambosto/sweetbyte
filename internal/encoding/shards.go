// Package encoding provides robust error correction capabilities using Reed-Solomon encoding.
// It allows data to be encoded into shards, including parity shards, which enables
// reconstruction of the original data even if some shards are corrupted or lost.
package encoding

import (
	"fmt"
)

// Shards manages the splitting of data into fixed-size shards and their recombination.
// It facilitates the preparation of data for Reed-Solomon encoding and the extraction
// of original data after decoding/reconstruction.
type Shards struct {
	dataShards   int // The number of data-carrying shards.
	parityShards int // The number of error-correction (parity) shards.
	totalShards  int // The total number of shards (data + parity).
}

// NewShards creates and returns a new Shards instance.
// It initializes the shard configuration based on the provided data and parity shard counts.
func NewShards(dataShards, parityShards int) *Shards {
	return &Shards{
		dataShards:   dataShards,                // Store the number of data shards.
		parityShards: parityShards,              // Store the number of parity shards.
		totalShards:  dataShards + parityShards, // Calculate the total number of shards.
	}
}

// Split divides the input data into `dataShards` pieces.
// Each piece is padded with zeros to ensure a uniform shard size.
// The function returns a slice containing both data and empty parity shards,
// ready for the Reed-Solomon encoding process.
func (s *Shards) Split(data []byte) [][]byte {
	// Calculate the size of each shard, ensuring it can hold all data by rounding up.
	shardSize := (len(data) + s.dataShards - 1) / s.dataShards

	// Create a slice to hold all shards (data + parity), initialized with `shardSize` capacity.
	shards := make([][]byte, s.totalShards)
	for i := range shards {
		shards[i] = make([]byte, shardSize)
	}

	// Distribute the input data across the data shards.
	for i, b := range data {
		shardIndex := i / shardSize        // Determine which shard the byte belongs to.
		posInShard := i % shardSize        // Determine the position within that shard.
		shards[shardIndex][posInShard] = b // Place the byte into its calculated position.
	}

	return shards // Return the slice of shards, including empty parity shards.
}

// SplitEncoded divides an already encoded (combined data and parity) byte slice
// back into individual shards. This is used during the decoding/reconstruction process.
// It assumes the input `data` is perfectly divisible by the `totalShards`.
func (s *Shards) SplitEncoded(data []byte) [][]byte {
	shardSize := len(data) / s.totalShards  // Calculate the size of each shard.
	shards := make([][]byte, s.totalShards) // Create a slice to hold all shards.

	for i := range shards { // Iterate through each shard index.
		start := i * shardSize              // Calculate the starting byte index for the current shard.
		end := (i + 1) * shardSize          // Calculate the ending byte index for the current shard.
		shards[i] = make([]byte, shardSize) // Create a new slice for the current shard.
		copy(shards[i], data[start:end])    // Copy the data for the current shard.
	}

	return shards // Return the slice of individual shards.
}

// Combine concatenates all provided shards into a single byte slice.
// This is typically used after encoding to create the complete encoded data blob.
func (s *Shards) Combine(shards [][]byte) []byte {
	if len(shards) == 0 { // Handle case of empty shards slice.
		return nil
	}

	shardSize := len(shards[0])          // Assume all shards have the same size.
	totalSize := shardSize * len(shards) // Calculate the total size of the combined data.
	result := make([]byte, totalSize)    // Create a byte slice to hold the combined result.

	for i, shard := range shards { // Iterate through each shard.
		start := i * shardSize                     // Calculate the starting position for copying.
		copy(result[start:start+shardSize], shard) // Copy the current shard into the result slice.
	}

	return result // Return the combined byte slice.
}

// Extract retrieves the original data from the data shards after decoding/reconstruction.
// It combines only the `dataShards` (excluding parity shards) and trims any padding.
// Returns an error if an insufficient number of data shards are available.
func (s *Shards) Extract(shards [][]byte) ([]byte, error) {
	if len(shards) < s.dataShards { // Ensure enough data shards are present for extraction.
		return nil, fmt.Errorf("insufficient shards, have %d but need at least %d data shards", len(shards), s.dataShards) // Error for insufficient shards.
	}

	shardSize := len(shards[0]) // Get the size of a single shard.
	// Create a buffer with enough capacity for all data shards.
	combined := make([]byte, 0, shardSize*s.dataShards)

	for i := 0; i < s.dataShards; i++ { // Iterate only through the data shards.
		combined = append(combined, shards[i]...) // Append each data shard to the combined slice.
	}

	return combined, nil // Return the extracted data.
}
