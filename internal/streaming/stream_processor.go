package streaming

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/hambosto/sweetbyte/internal/ui"
)

// Task represents a processing task for concurrent operations.
type Task struct {
	Data  []byte
	Index uint64
}

// TaskResult represents the result of a processed task.
type TaskResult struct {
	Index uint64
	Data  []byte
	Size  int
	Err   error
}

// streamProcessor is the main streaming processor implementation
type streamProcessor struct {
	streamConfig  StreamConfig
	taskProcessor TaskProcessor
	reader        ChunkReader
	writer        ChunkWriter
	pool          *workerPool
}

// NewStreamProcessor creates a new streaming processor
func NewStreamProcessor(config StreamConfig) (Processor, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	config.ApplyDefaults()

	taskProcessor, err := NewTaskProcessor(config.Key, config.Processing)
	if err != nil {
		return nil, fmt.Errorf("failed to create task processor: %w", err)
	}

	return &streamProcessor{
		streamConfig:  config,
		taskProcessor: taskProcessor,
		reader:        NewChunkReader(config.Processing, config.ChunkSize),
		pool:          NewWorkerPool(taskProcessor, config.Concurrency),
	}, nil
}

// Process processes data from input to output
func (s *streamProcessor) Process(ctx context.Context, input io.Reader, output io.Writer, totalSize int64) error {
	if input == nil || output == nil {
		return fmt.Errorf("input and output streams must not be nil")
	}

	// Create progress bar
	bar := ui.NewProgressBar(totalSize, s.streamConfig.Processing.String())
	s.writer = NewChunkWriter(s.streamConfig.Processing, bar)

	return s.runPipeline(ctx, input, output)
}

// runPipeline orchestrates the streaming pipeline
func (s *streamProcessor) runPipeline(ctx context.Context, input io.Reader, output io.Writer) error {
	// Create cancellable context for pipeline coordination
	pipelineCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Stage 1: Read chunks from input
	tasks, readerErr := s.reader.ReadChunks(pipelineCtx, input)

	// Stage 2: Process chunks concurrently
	results := s.pool.Process(pipelineCtx, tasks)

	// Stage 3: Write results in order
	var writerErr error
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		defer wg.Done()
		writerErr = s.writer.WriteChunks(pipelineCtx, output, results)
	}()

	// Wait for all stages to complete or error
	wg.Wait()

	// Check for errors from reader
	select {
	case err := <-readerErr:
		if err != nil {
			cancel() // Cancel other stages
			return fmt.Errorf("reader error: %w", err)
		}
	default:
	}

	// Check writer error
	if writerErr != nil {
		cancel()
		return fmt.Errorf("writer error: %w", writerErr)
	}

	// Check context cancellation
	if pipelineCtx.Err() != nil {
		return fmt.Errorf("operation was canceled")
	}

	return nil
}
