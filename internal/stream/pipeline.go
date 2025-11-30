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

const DefaultChunkSize = 256 * 1024

type Pipeline struct {
	key            []byte
	chunkSize      int
	concurrency    int
	dataProcessing *DataProcessing
	executor       *ConcurrentExecutor
	processing     types.Processing
}

func NewPipeline(key []byte, processing types.Processing) (*Pipeline, error) {
	if len(key) != derive.ArgonKeyLen {
		return nil, fmt.Errorf("key must be exactly %d bytes, got %d", derive.ArgonKeyLen, len(key))
	}

	dataProcessing, err := NewDataProcessing(key, processing)
	if err != nil {
		return nil, fmt.Errorf("data processing creation: %w", err)
	}

	concurrency := runtime.NumCPU()
	executor := NewConcurrentExecutor(dataProcessing, concurrency)

	return &Pipeline{
		key:            key,
		chunkSize:      DefaultChunkSize,
		concurrency:    concurrency,
		dataProcessing: dataProcessing,
		executor:       executor,
		processing:     processing,
	}, nil
}

func (p *Pipeline) Process(ctx context.Context, input io.Reader, output io.Writer, totalSize int64) error {
	if input == nil || output == nil {
		return fmt.Errorf("input and output must not be nil")
	}

	reader, err := NewChunkReader(p.processing, DefaultChunkSize)
	if err != nil {
		return fmt.Errorf("reader creation: %w", err)
	}

	bar := ui.NewProgressBar(totalSize, p.processing.String())
	writer := NewChunkWriter(p.processing, bar)

	return p.run(ctx, input, output, reader, writer, p.processing)
}

func (p *Pipeline) run(ctx context.Context, input io.Reader, output io.Writer, reader *ChunkReader, writer *ChunkWriter, mode types.Processing) error {
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
