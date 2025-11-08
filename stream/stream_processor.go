package stream

import (
	"context"
	"fmt"
	"io"
	"runtime"
	"sync"

	"sweetbyte/config"
	"sweetbyte/tui"
	"sweetbyte/types"
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
	if len(key) != config.MasterKeySize {
		return nil, fmt.Errorf("key must be %d bytes long", config.MasterKeySize)
	}

	taskProcessor, err := NewTaskProcessor(key, processing)
	if err != nil {
		return nil, fmt.Errorf("failed to create task processor: %w", err)
	}

	concurrency := runtime.GOMAXPROCS(0)
	chunkSize := config.DefaultChunkSize

	return &StreamProcessor{
		key:           key,
		processing:    processing,
		concurrency:   concurrency,
		chunkSize:     chunkSize,
		taskProcessor: taskProcessor,
		reader:        NewChunkReader(processing, chunkSize, concurrency),
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

	wg.Go(func() {
		writerErr = s.writer.WriteChunks(pipelineCtx, output, results)
	})
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
