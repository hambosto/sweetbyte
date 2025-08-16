package streaming

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/hambosto/sweetbyte/internal/ui"
)

// Task represents a unit of work for the concurrent processing pool.
// Each task contains a chunk of data and its sequential index.
type Task struct {
	Data  []byte
	Index uint64
}

// TaskResult is the outcome of processing a `Task`.
// Size is used for progress tracking (input size for encryption, output size
// for decryption). Err contains the first error encountered during processing.
type TaskResult struct {
	Index uint64
	Data  []byte
	Size  int
	Err   error
}

// streamProcessor orchestrates the end-to-end streaming pipeline composed of:
//   1. Reader: converts the input stream to chunked `Task`s
//   2. Worker pool: processes chunks concurrently (encrypt/decrypt)
//   3. Writer: emits results in order, preserving boundaries
//
// It manages context cancellation across stages and aggregates errors from
// reader/writer, returning the first error with context.
type streamProcessor struct {
	streamConfig  StreamConfig
	taskProcessor TaskProcessor
	reader        ChunkReader
	writer        ChunkWriter
	pool          *workerPool
}

// NewStreamProcessor creates a streaming processor from `StreamConfig`.
//
// It validates the config, applies defaults, constructs the chunk reader,
// task processor, and worker pool. The writer is created in `Process` when a
// progress bar can be initialized using the known total size.
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

// Process runs the pipeline from `input` to `output`.
//
// It creates a progress bar (via `ui.ProgressBar`), then calls `runPipeline`.
// The method validates streams are non-nil and returns on the first error from
// reader or writer, preserving error context. Cancellation is observed via ctx.
func (s *streamProcessor) Process(ctx context.Context, input io.Reader, output io.Writer, totalSize int64) error {
	if input == nil || output == nil {
		return fmt.Errorf("input and output streams must not be nil")
	}

	// Create progress bar
	bar := ui.NewProgressBar(totalSize, s.streamConfig.Processing.String())
	s.writer = NewChunkWriter(s.streamConfig.Processing, bar)

	return s.runPipeline(ctx, input, output)
}

// runPipeline orchestrates the three stages (reader, pool, writer):
// - Read chunks with cancellation support
// - Process chunks concurrently via worker pool
// - Write results in original order
//
// It cancels the pipeline on error and surfaces reader/writer errors with
// layered context. Caller must have initialized the writer (progress bar).
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
