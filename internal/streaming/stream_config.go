package streaming

import (
	"fmt"
	"runtime"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/options"
)

// StreamConfig holds parameters that control the streaming pipeline.
//
// Fields:
//   - Key: Master key used to initialize the underlying `processor.Processor`.
//     Must be exactly `config.MasterKeySize` bytes (see Validate).
//   - Processing: Operation mode (encryption or decryption). This drives
//     reader/writer behavior and progress text.
//   - Concurrency: Number of workers in the processing pool. If unset,
//     defaults to `runtime.NumCPU()`.
//   - ChunkSize: Size of plaintext chunks read from the input during
//     encryption; also used to bound memory during decryption.
type StreamConfig struct {
	Key         []byte
	Processing  options.Processing
	Concurrency int
	ChunkSize   int
}

// Validate checks invariants on `StreamConfig` that must hold before use.
// It only validates key length; other values are defaulted in `ApplyDefaults`.
func (s *StreamConfig) Validate() error {
	if len(s.Key) != config.MasterKeySize {
		return fmt.Errorf("key must be 64 bytes long")
	}
	return nil
}

// ApplyDefaults applies sensible defaults where fields are zero/empty.
// Call this after `Validate` and before constructing the stream processor.
func (s *StreamConfig) ApplyDefaults() {
	if s.Concurrency <= 0 {
		s.Concurrency = runtime.NumCPU()
	}
	if s.ChunkSize <= 0 {
		s.ChunkSize = config.DefaultChunkSize
	}
}
