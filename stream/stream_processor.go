package stream

import (
	"context"
	"fmt"
	"io"
	"runtime"
	"sync"

	"sweetbyte/derive"
	"sweetbyte/tui"
	"sweetbyte/types"
)

const (
	DefaultChunkSize = 1 * 1024 * 1024
)

type StreamProcessor struct {
	key           []byte
	processing    types.Processing
	concurrency   int
	chunkSize     int
	taskProcessor *TaskProcessor
	reader        *ChunkReader
	writer        *ChunkWriter
	pool          *WorkerPool
}

func NewStreamProcessor(key []byte, processing types.Processing) (*StreamProcessor, error) {
	if len(key) != derive.ArgonKeyLen {
		return nil, fmt.Errorf("key must be %d bytes long", derive.ArgonKeyLen)
	}

	taskProcessor, err := NewTaskProcessor(key, processing)
	if err != nil {
		return nil, fmt.Errorf("failed to create task processor: %w", err)
	}

	concurrency := runtime.GOMAXPROCS(0)
	return &StreamProcessor{
		key:           key,
		processing:    processing,
		concurrency:   concurrency,
		chunkSize:     DefaultChunkSize,
		taskProcessor: taskProcessor,
		reader:        NewChunkReader(processing, DefaultChunkSize, concurrency),
		pool:          NewWorkerPool(taskProcessor, concurrency),
	}, nil
}

func (s *StreamProcessor) Process(ctx context.Context, input io.Reader, output io.Writer, totalSize int64) error {
	if input == nil || output == nil {
		return fmt.Errorf("input and output streams must not be nil")
	}

	bar := tui.NewProgressBar(totalSize, s.processing.String())
	s.writer = NewChunkWriter(s.processing, bar)
	return s.runPipeline(ctx, input, output)
}

func (s *StreamProcessor) runPipeline(ctx context.Context, input io.Reader, output io.Writer) error {
	pipelineCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	tasks, readerErr := s.reader.ReadChunks(pipelineCtx, input)
	results := s.pool.Process(pipelineCtx, tasks)

	var writerErr error
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		writerErr = s.writer.WriteChunks(pipelineCtx, output, results)
	}()
	wg.Wait()

	select {
	case err := <-readerErr:
		if err != nil {
			cancel()
			return fmt.Errorf("reader error: %w", err)
		}
	default:
	}

	if writerErr != nil {
		cancel()
		return fmt.Errorf("writer error: %w", writerErr)
	}

	if pipelineCtx.Err() != nil {
		return fmt.Errorf("operation was canceled: %w", pipelineCtx.Err())
	}

	return nil
}
