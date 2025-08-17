// Package streaming provides the infrastructure for efficient, chunk-based file processing.
// It includes components for reading, processing, and writing data in a streaming fashion,
// utilizing concurrency for performance and managing the order of processed chunks.
package streaming

import (
	"fmt"
	"runtime"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/options"
)

// StreamConfig holds configuration parameters for the streaming processor.
// These parameters dictate how the file will be processed, including cryptographic key,
// operation type (encryption/decryption), concurrency level, and chunk size.
type StreamConfig struct {
	Key         []byte             // The cryptographic key used for encryption or decryption.
	Processing  options.Processing // The type of operation to perform: encryption or decryption.
	Concurrency int                // The number of concurrent workers to use for processing chunks.
	ChunkSize   int                // The size of data chunks to process at a time.
}

// Validate checks if the StreamConfig contains valid parameters.
// It ensures that the cryptographic key is of the correct length.
func (s *StreamConfig) Validate() error {
	if len(s.Key) != config.MasterKeySize { // Check if the provided key has the required master key size.
		return fmt.Errorf("key must be 64 bytes long") // Return an error if the key length is incorrect.
	}
	return nil // Return nil if validation passes.
}

// ApplyDefaults sets default values for concurrency and chunk size if they are not explicitly set.
// Concurrency defaults to the number of CPU cores, and ChunkSize defaults to a predefined value.
func (s *StreamConfig) ApplyDefaults() {
	if s.Concurrency <= 0 { // If concurrency is not set or invalid (<= 0).
		s.Concurrency = runtime.NumCPU() // Set concurrency to the number of available CPU cores.
	}
	if s.ChunkSize <= 0 { // If chunk size is not set or invalid (<= 0).
		s.ChunkSize = config.DefaultChunkSize // Set chunk size to the default configured value.
	}
}
