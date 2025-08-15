package streaming

import (
	"context"
	"io"
)

// TaskProcessor defines the interface for processing individual chunks
type TaskProcessor interface {
	Process(ctx context.Context, chunk Task) TaskResult
}

// ChunkReader defines the interface for reading data chunks
type ChunkReader interface {
	ReadChunks(ctx context.Context, input io.Reader) (<-chan Task, <-chan error)
}

// ChunkWriter defines the interface for writing processed chunks
type ChunkWriter interface {
	WriteChunks(ctx context.Context, output io.Writer, results <-chan TaskResult) error
}

// OrderBuffer defines the interface for maintaining chunk order
type OrderBuffer interface {
	Add(result TaskResult) []TaskResult
	Flush() []TaskResult
}

// Processor defines the main stream processor interface
type Processor interface {
	Process(ctx context.Context, input io.Reader, output io.Writer, totalSize int64) error
}
