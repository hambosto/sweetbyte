package streaming

import (
	"fmt"
	"runtime"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/options"
)

type StreamConfig struct {
	Key         []byte
	Processing  options.Processing
	Concurrency int
	ChunkSize   int
}

func (s *StreamConfig) Validate() error {
	if len(s.Key) != config.MasterKeySize {
		return fmt.Errorf("key must be 64 bytes long")
	}
	return nil
}

func (s *StreamConfig) ApplyDefaults() {
	if s.Concurrency <= 0 {
		s.Concurrency = runtime.GOMAXPROCS(0)
	}

	if s.ChunkSize <= 0 {
		s.ChunkSize = config.DefaultChunkSize
	}
}
