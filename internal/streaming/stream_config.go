package streaming

import (
	"fmt"
	"runtime"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/options"
)

// Config holds stream processing configuration
type StreamConfig struct {
	Key         []byte
	Processing  options.Processing
	Concurrency int
	ChunkSize   int
}

// Validate validates the stream configuration
func (s *StreamConfig) Validate() error {
	if len(s.Key) != config.MasterKeySize {
		return fmt.Errorf("key must be 64 bytes long")
	}
	return nil
}

// ApplyDefaults applies default values to unset configuration fields
func (s *StreamConfig) ApplyDefaults() {
	if s.Concurrency <= 0 {
		s.Concurrency = runtime.NumCPU()
	}
	if s.ChunkSize <= 0 {
		s.ChunkSize = config.DefaultChunkSize
	}
}
