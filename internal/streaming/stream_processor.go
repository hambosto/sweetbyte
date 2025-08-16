package streaming

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/hambosto/sweetbyte/internal/ui"
)

// Task represents a chunk of data to be processed by a worker.
// It includes the data itself and its original sequence index to ensure
// the output is correctly ordered.
type Task struct {
	Data  []byte
	Index uint64
}

// TaskResult holds the outcome of a processed task.
// It contains the resulting data, the original index for reordering,
// the size for progress tracking, and any error that occurred.
type TaskResult struct {
	Index uint64
	Data  []byte
	Size  int
	Err   error
}

// streamProcessor manages the entire concurrent streaming pipeline.
// It coordinates the reader, worker pool, and writer to process a stream
// of data in chunks, handling context cancellation and error propagation.
type streamProcessor struct {
	streamConfig  StreamConfig
	taskProcessor TaskProcessor
	reader        ChunkReader
	writer        ChunkWriter
	pool          *workerPool
}

// NewStreamProcessor creates a new stream processor with the given configuration.
// It initializes the task processor, chunk reader, and worker pool.
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

// Process executes the streaming operation from an input reader to an output writer.
// It sets up a progress bar and then runs the pipeline, ensuring that the
// input and output streams are handled correctly.
func (s *streamProcessor) Process(ctx context.Context, input io.Reader, output io.Writer, totalSize int64) error {
	if input == nil || output == nil {
		return fmt.Errorf("input and output streams must not be nil")
	}

	// Create progress bar
	bar := ui.NewProgressBar(totalSize, s.streamConfig.Processing.String())
	s.writer = NewChunkWriter(s.streamConfig.Processing, bar)

	return s.runPipeline(ctx, input, output)
}

// runPipeline is the core of the stream processor. It connects the reader,
// worker pool, and writer, and manages the data flow between them.
// It also handles error propagation and context cancellation.
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
