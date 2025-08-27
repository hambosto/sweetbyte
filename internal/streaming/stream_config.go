// Package streaming provides the core functionality for streaming encryption and decryption.
package streaming

import (
	"fmt"
	"runtime"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/options"
)

// StreamConfig holds the configuration for the streaming process.
type StreamConfig struct {
	Key         []byte
	Processing  options.Processing
	Concurrency int
	ChunkSize   int
}

// Validate checks if the StreamConfig is valid.
func (s *StreamConfig) Validate() error {
	// The key must be 64 bytes long.
	if len(s.Key) != config.MasterKeySize {
		return fmt.Errorf("key must be 64 bytes long")
	}
	return nil
}

// ApplyDefaults sets default values for the StreamConfig if they are not already set.
func (s *StreamConfig) ApplyDefaults() {
	// If concurrency is not set, use the number of CPU cores.
	if s.Concurrency <= 0 {
		s.Concurrency = runtime.GOMAXPROCS(0)
	}
	// If chunk size is not set, use the default chunk size.
	if s.ChunkSize <= 0 {
		s.ChunkSize = config.DefaultChunkSize
	}
}
