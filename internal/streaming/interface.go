package streaming

import (
	"context"
	"io"

	"github.com/hambosto/sweetbyte/internal/types"
)

// TaskProcessor defines the interface for processing individual chunks
type TaskProcessor interface {
	Process(ctx context.Context, chunk types.Task) types.TaskResult
}

// ChunkReader defines the interface for reading data chunks
type ChunkReader interface {
	ReadChunks(ctx context.Context, input io.Reader) (<-chan types.Task, <-chan error)
}

// ChunkWriter defines the interface for writing processed chunks
type ChunkWriter interface {
	WriteChunks(ctx context.Context, output io.Writer, results <-chan types.TaskResult) error
}

// OrderBuffer defines the interface for maintaining chunk order
type OrderBuffer interface {
	Add(result types.TaskResult) []types.TaskResult
	Flush() []types.TaskResult
}

// Processor defines the main stream processor interface
type Processor interface {
	Process(ctx context.Context, input io.Reader, output io.Writer, totalSize int64) error
}
