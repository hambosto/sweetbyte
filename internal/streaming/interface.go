// Package streaming provides the core functionality for streaming encryption and decryption.
package streaming

import (
	"context"
	"io"
)

// TaskProcessor is an interface for processing tasks.
type TaskProcessor interface {
	Process(ctx context.Context, chunk Task) TaskResult
}

// ChunkReader is an interface for reading chunks from an input stream.
type ChunkReader interface {
	ReadChunks(ctx context.Context, input io.Reader) (<-chan Task, <-chan error)
}

// ChunkWriter is an interface for writing chunks to an output stream.
type ChunkWriter interface {
	WriteChunks(ctx context.Context, output io.Writer, results <-chan TaskResult) error
}

// OrderBuffer is an interface for buffering and ordering task results.
type OrderBuffer interface {
	Add(result TaskResult) []TaskResult
	Flush() []TaskResult
}

// Processor is an interface for the main streaming processor.
type Processor interface {
	Process(ctx context.Context, input io.Reader, output io.Writer, totalSize int64) error
}
