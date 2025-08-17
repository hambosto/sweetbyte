// Package streaming defines the interfaces for the streaming data processing pipeline.
// These interfaces abstract the behavior of different components involved in reading,
// processing, and writing data chunks concurrently.
package streaming

import (
	"context"
	"io"
)

// TaskProcessor defines the interface for processing individual data chunks (Tasks).
// Implementations of this interface perform the core encryption or decryption logic.
type TaskProcessor interface {
	Process(ctx context.Context, chunk Task) TaskResult
}

// ChunkReader defines the interface for reading data chunks from an input source.
// It is responsible for breaking down the input stream into manageable chunks
// and emitting them as Tasks.
type ChunkReader interface {
	ReadChunks(ctx context.Context, input io.Reader) (<-chan Task, <-chan error)
}

// ChunkWriter defines the interface for writing processed data chunks to an output destination.
// It is responsible for assembling processed TaskResults into the final output stream.
type ChunkWriter interface {
	WriteChunks(ctx context.Context, output io.Writer, results <-chan TaskResult) error
}

// OrderBuffer defines the interface for a buffer that maintains the correct order of processed chunks.
// It ensures that data is written to the output stream in its original sequence, even if processed out of order.
type OrderBuffer interface {
	Add(result TaskResult) []TaskResult
	Flush() []TaskResult
}

// Processor defines the high-level interface for the entire streaming operation.
// Implementations orchestrate the reading, concurrent processing, and writing of files.
type Processor interface {
	Process(ctx context.Context, input io.Reader, output io.Writer, totalSize int64) error
}
