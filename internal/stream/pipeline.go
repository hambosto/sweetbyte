package stream

import (
	"context"
	"fmt"
	"io"
	"runtime"

	"github.com/hambosto/sweetbyte/internal/derive"
	"github.com/hambosto/sweetbyte/internal/types"
	"github.com/hambosto/sweetbyte/internal/ui"
	"golang.org/x/sync/errgroup"
)

const (
	DefaultChunkSize = 256 * 1024
)

type Pipeline struct {
	key           []byte
	processing    types.Processing
	concurrency   int
	chunkSize     int
	taskProcessor *TaskProcessor
	reader        *ChunkReader
	pool          *WorkerPool
}

func NewPipeline(key []byte, processing types.Processing) (*Pipeline, error) {
	if len(key) != derive.ArgonKeyLen {
		return nil, fmt.Errorf("key must be %d bytes long", derive.ArgonKeyLen)
	}

	taskProcessor, err := NewTaskProcessor(key, processing)
	if err != nil {
		return nil, fmt.Errorf("failed to create task processor: %w", err)
	}

	concurrency := runtime.NumCPU()
	return &Pipeline{
		key:           key,
		processing:    processing,
		concurrency:   concurrency,
		chunkSize:     DefaultChunkSize,
		taskProcessor: taskProcessor,
		reader:        NewChunkReader(processing, DefaultChunkSize, concurrency),
		pool:          NewWorkerPool(taskProcessor, concurrency),
	}, nil
}

func (p *Pipeline) Process(ctx context.Context, input io.Reader, output io.Writer, totalSize int64) error {
	if input == nil || output == nil {
		return fmt.Errorf("input and output streams must not be nil")
	}

	bar := ui.NewProgressBar(totalSize, p.processing.String())

	writer := NewChunkWriter(p.processing, bar)

	return p.runPipeline(ctx, input, output, writer)
}

func (p *Pipeline) runPipeline(ctx context.Context, input io.Reader, output io.Writer, writer *ChunkWriter) error {
	g, ctx := errgroup.WithContext(ctx)

	tasks, readerErr := p.reader.ReadChunks(ctx, input)

	results := p.pool.Process(ctx, tasks)

	g.Go(func() error {
		return writer.WriteChunks(ctx, output, results)
	})

	g.Go(func() error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-readerErr:
			return err
		}
	})

	return g.Wait()
}
