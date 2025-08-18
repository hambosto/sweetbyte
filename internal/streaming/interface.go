package streaming

import (
	"context"
	"io"
)

type TaskProcessor interface {
	Process(ctx context.Context, chunk Task) TaskResult
}

type ChunkReader interface {
	ReadChunks(ctx context.Context, input io.Reader) (<-chan Task, <-chan error)
}

type ChunkWriter interface {
	WriteChunks(ctx context.Context, output io.Writer, results <-chan TaskResult) error
}

type OrderBuffer interface {
	Add(result TaskResult) []TaskResult
	Flush() []TaskResult
}

type Processor interface {
	Process(ctx context.Context, input io.Reader, output io.Writer, totalSize int64) error
}
