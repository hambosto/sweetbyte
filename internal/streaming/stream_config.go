// Package streaming provides functionalities for streaming data processing.
package streaming

import (
	"fmt"
	"runtime"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/options"
)

// StreamConfig holds the configuration for a stream processor.
type StreamConfig struct {
	Key         []byte
	Processing  options.Processing
	Concurrency int
	ChunkSize   int
}

// Validate checks if the stream configuration is valid.
func (s *StreamConfig) Validate() error {
	// Ensure the key has the required size.
	if len(s.Key) != config.MasterKeySize {
		return fmt.Errorf("key must be 64 bytes long")
	}
	return nil
}

// ApplyDefaults applies default values to the stream configuration.
func (s *StreamConfig) ApplyDefaults() {
	// If concurrency is not set, use the number of available CPUs.
	if s.Concurrency <= 0 {
		s.Concurrency = runtime.GOMAXPROCS(0)
	}

	// If chunk size is not set, use the default chunk size.
	if s.ChunkSize <= 0 {
		s.ChunkSize = config.DefaultChunkSize
	}
}
