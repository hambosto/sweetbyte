package stream

import (
	"context"
	"fmt"
	"io"
	"runtime"

	"github.com/hambosto/sweetbyte/internal/derive"
	"github.com/hambosto/sweetbyte/internal/stream/chunk"
	"github.com/hambosto/sweetbyte/internal/stream/concurrent"
	"github.com/hambosto/sweetbyte/internal/stream/processing"
	"github.com/hambosto/sweetbyte/internal/types"
	"github.com/hambosto/sweetbyte/internal/ui/bar"
	"golang.org/x/sync/errgroup"
)

const DefaultChunkSize = 256 * 1024

type Pipeline struct {
	key            []byte
	chunkSize      int
	concurrency    int
	dataProcessing *processing.DataProcessing
	executor       *concurrent.ConcurrentExecutor
	processing     types.Processing
}

func NewPipeline(key []byte, processMode types.Processing) (*Pipeline, error) {
	if len(key) != derive.ArgonKeyLen {
		return nil, fmt.Errorf("key must be exactly %d bytes, got %d", derive.ArgonKeyLen, len(key))
	}

	dataProcessing, err := processing.NewDataProcessing(key, processMode)
	if err != nil {
		return nil, fmt.Errorf("data processing creation: %w", err)
	}

	concurrency := runtime.NumCPU()
	executor := concurrent.NewConcurrentExecutor(dataProcessing, concurrency)

	return &Pipeline{
		key:            key,
		chunkSize:      DefaultChunkSize,
		concurrency:    concurrency,
		dataProcessing: dataProcessing,
		executor:       executor,
		processing:     processMode,
	}, nil
}

func (p *Pipeline) Process(ctx context.Context, input io.Reader, output io.Writer, totalSize int64) error {
	if input == nil || output == nil {
		return fmt.Errorf("input and output must not be nil")
	}

	bar := bar.NewProgressBar(totalSize, p.processing.String())

	reader, err := chunk.NewChunkReader(p.processing, DefaultChunkSize)
	if err != nil {
		return fmt.Errorf("reader creation: %w", err)
	}

	writer, err := chunk.NewChunkWriter(p.processing, bar)
	if err != nil {
		return fmt.Errorf("writer creation: %w", err)
	}

	return p.run(ctx, input, output, reader, writer, p.processing)
}

func (p *Pipeline) run(ctx context.Context, input io.Reader, output io.Writer, reader *chunk.ChunkReader, writer *chunk.ChunkWriter, mode types.Processing) error {
	g, ctx := errgroup.WithContext(ctx)

	tasks, readerErr := reader.Read(ctx, input)
	results := p.executor.Process(ctx, tasks, mode)

	g.Go(func() error {
		return writer.Write(ctx, output, results)
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
