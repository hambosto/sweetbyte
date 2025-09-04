// Package streaming provides the core functionality for streaming encryption and decryption.
package streaming

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/hambosto/sweetbyte/internal/ui"
)

// Task represents a chunk of data to be processed.
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

// StreamProcessor handles the entire streaming process.
type StreamProcessor interface {
	Process(ctx context.Context, input io.Reader, output io.Writer, totalSize int64) error
}

// streamProcessor handles the entire streaming process.
type streamProcessor struct {
	streamConfig  StreamConfig
	taskProcessor TaskProcessor
	reader        ChunkReader
	writer        ChunkWriter
	pool          WorkerPool
}

// NewStreamProcessor creates a new streamProcessor with the given configuration.
func NewStreamProcessor(config StreamConfig) (StreamProcessor, error) {
	// Validate the configuration.
	if err := config.Validate(); err != nil {
		return nil, err
	}
	// Apply default values to the configuration.
	config.ApplyDefaults()

	// Create a new task processor.
	taskProcessor, err := NewTaskProcessor(config.Key, config.Processing)
	if err != nil {
		return nil, fmt.Errorf("failed to create task processor: %w", err)
	}

	return &streamProcessor{
		streamConfig:  config,
		taskProcessor: taskProcessor,
		reader:        NewChunkReader(config.Processing, config.ChunkSize, config.Concurrency),
		pool:          NewWorkerPool(taskProcessor, config.Concurrency),
	}, nil
}

// Process starts the streaming process for the given input and output streams.
func (s *streamProcessor) Process(ctx context.Context, input io.Reader, output io.Writer, totalSize int64) error {
	// Ensure input and output streams are not nil.
	if input == nil || output == nil {
		return fmt.Errorf("input and output streams must not be nil")
	}

	// Create a new progress bar.
	bar := ui.NewProgressBar(totalSize, s.streamConfig.Processing.String())
	// Create a new chunk writer with the progress bar.
	s.writer = NewChunkWriter(s.streamConfig.Processing, bar)
	// Run the processing pipeline.
	return s.runPipeline(ctx, input, output)
}

// runPipeline sets up and runs the streaming pipeline.
func (s *streamProcessor) runPipeline(ctx context.Context, input io.Reader, output io.Writer) error {
	// Create a new context for the pipeline.
	pipelineCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Read chunks from the input stream.
	tasks, readerErr := s.reader.ReadChunks(pipelineCtx, input)
	// Process the tasks using the worker pool.
	results := s.pool.Process(pipelineCtx, tasks)

	var writerErr error
	var wg sync.WaitGroup

	// Start a goroutine to write the results to the output stream.
	wg.Add(1)
	go func() {
		defer wg.Done()
		writerErr = s.writer.WriteChunks(pipelineCtx, output, results)
	}()
	// Wait for the writer to finish.
	wg.Wait()

	// Check for reader errors.
	select {
	case err := <-readerErr:
		if err != nil {
			cancel()
			return fmt.Errorf("reader error: %w", err)
		}
	default:
	}

	// Check for writer errors.
	if writerErr != nil {
		cancel()
		return fmt.Errorf("writer error: %w", writerErr)
	}

	// Check if the context was canceled.
	if pipelineCtx.Err() != nil {
		return fmt.Errorf("operation was canceled: %w", pipelineCtx.Err())
	}

	return nil
}
