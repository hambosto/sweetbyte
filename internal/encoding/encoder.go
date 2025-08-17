// Package encoding provides robust error correction capabilities using Reed-Solomon encoding.
// It allows data to be encoded into shards, including parity shards, which enables
// reconstruction of the original data even if some shards are corrupted or lost.
package encoding

import (
	"fmt"

	"github.com/klauspost/reedsolomon"
)

const (
	// MaxDataLen defines the maximum supported input data length for encoding.
	// This limit prevents excessive memory allocation and potential issues with very large inputs.
	MaxDataLen = 1 << 30 // 1 GB
)

// Encoder manages the Reed-Solomon encoding and decoding operations.
// It holds the configuration for data and parity shards and an instance of the Reed-Solomon encoder.
type Encoder struct {
	dataShards   int                 // The number of data shards.
	parityShards int                 // The number of parity shards.
	encoder      reedsolomon.Encoder // The underlying Reed-Solomon encoder instance.
	shards       *Shards             // Helper to split and combine data into shards.
}

// NewEncoder creates and returns a new Encoder instance.
// It initializes the Reed-Solomon encoder with the specified number of data and parity shards.
// It validates shard counts and ensures the total number of shards does not exceed 255.
func NewEncoder(dataShards, parityShards int) (*Encoder, error) {
	if dataShards <= 0 { // Validate that data shards are positive.
		return nil, fmt.Errorf("data shards must be positive")
	}
	if parityShards <= 0 { // Validate that parity shards are positive.
		return nil, fmt.Errorf("parity shards must be positive")
	}
	if dataShards+parityShards > 255 { // Reed-Solomon implementation limit.
		return nil, fmt.Errorf("total shards cannot exceed 255")
	}

	enc, err := reedsolomon.New(dataShards, parityShards) // Create a new Reed-Solomon encoder.
	if err != nil {
		return nil, fmt.Errorf("failed to create reed-solomon encoder: %w", err) // Propagate initialization errors.
	}

	return &Encoder{
		dataShards:   dataShards,                          // Store the number of data shards.
		parityShards: parityShards,                        // Store the number of parity shards.
		encoder:      enc,                                 // Assign the created Reed-Solomon encoder.
		shards:       NewShards(dataShards, parityShards), // Initialize shard helper.
	}, nil
}

// Encode applies Reed-Solomon encoding to the input data.
// It splits the data into configured data shards, computes parity shards, and returns all shards combined.
// This process adds redundancy, allowing for data reconstruction even with some corruption.
func (e *Encoder) Encode(data []byte) ([]byte, error) {
	if len(data) == 0 { // Ensure input data is not empty.
		return nil, fmt.Errorf("input data cannot be empty")
	}
	if len(data) > MaxDataLen { // Prevent encoding excessively large data that might cause memory issues.
		return nil, fmt.Errorf("data size %d exceeds maximum %d bytes", len(data), MaxDataLen)
	}

	shards := e.shards.Split(data)                   // Split the input data into data shards.
	if err := e.encoder.Encode(shards); err != nil { // Compute parity shards from data shards.
		return nil, fmt.Errorf("encoding failed: %w", err) // Handle encoding errors.
	}

	return e.shards.Combine(shards), nil // Combine all (data + parity) shards into a single byte slice.
}

// Decode reconstructs the original data from the Reed-Solomon encoded byte slice.
// It attempts to repair corrupted or missing shards and extracts the original data content.
// Returns an error if reconstruction fails (e.g., too many corrupted shards).
func (e *Encoder) Decode(encoded []byte) ([]byte, error) {
	totalShards := e.dataShards + e.parityShards // Calculate the total number of shards (data + parity).

	if len(encoded) == 0 { // Ensure encoded data is not empty.
		return nil, fmt.Errorf("encoded data cannot be empty")
	}
	if len(encoded)%totalShards != 0 { // Check if the encoded data length is a multiple of total shards.
		return nil, fmt.Errorf("encoded data length %d not divisible by total shards %d", len(encoded), totalShards)
	}

	shards := e.shards.SplitEncoded(encoded)              // Split the encoded data back into individual shards.
	if err := e.encoder.Reconstruct(shards); err != nil { // Attempt to reconstruct any missing or corrupted shards.
		return nil, fmt.Errorf("reconstruction failed: %w", err) // Handle reconstruction errors (e.g., too many lost shards).
	}

	data, err := e.shards.Extract(shards) // Extract the original data from the (potentially reconstructed) data shards.
	if err != nil {
		return nil, fmt.Errorf("failed to extract data from shards: %w", err) // Handle data extraction errors.
	}

	return data, nil // Return the reconstructed original data.
}
