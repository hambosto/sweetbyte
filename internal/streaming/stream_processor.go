// Package streaming provides functionalities for streaming data processing.
package streaming

import (
	"context"
	"fmt"
	"io"
	"runtime"
	"sync"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/options"
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

// StreamProcessor defines the interface for a stream processor.
type StreamProcessor interface {
	// Process processes the data from the input stream and writes the result to the output stream.
	Process(ctx context.Context, input io.Reader, output io.Writer, totalSize int64) error
}

// streamProcessor implements the StreamProcessor interface.
type streamProcessor struct {
	key           []byte
	processing    options.Processing
	concurrency   int
	chunkSize     int
	taskProcessor TaskProcessor
	reader        ChunkReader
	writer        ChunkWriter
	pool          WorkerPool
}

// NewStreamProcessor creates a new StreamProcessor.
func NewStreamProcessor(key []byte, processing options.Processing) (StreamProcessor, error) {
	// Validate the key.
	if len(key) != config.MasterKeySize {
		return nil, fmt.Errorf("key must be %d bytes long", config.MasterKeySize)
	}

	// Create a new task processor.
	taskProcessor, err := NewTaskProcessor(key, processing)
	if err != nil {
		return nil, fmt.Errorf("failed to create task processor: %w", err)
	}

	concurrency := runtime.GOMAXPROCS(0)
	chunkSize := config.DefaultChunkSize

	return &streamProcessor{
		key:           key,
		processing:    processing,
		concurrency:   concurrency,
		chunkSize:     chunkSize,
		taskProcessor: taskProcessor,
		reader:        NewChunkReader(processing, chunkSize, concurrency),
		pool:          NewWorkerPool(taskProcessor, concurrency),
	}, nil
}

// Process processes the data from the input stream and writes the result to the output stream.
func (s *streamProcessor) Process(ctx context.Context, input io.Reader, output io.Writer, totalSize int64) error {
	// Ensure the input and output streams are not nil.
	if input == nil || output == nil {
		return fmt.Errorf("input and output streams must not be nil")
	}

	// Create a new progress bar and chunk writer.
	bar := ui.NewProgressBar(totalSize, s.processing.String())
	s.writer = NewChunkWriter(s.processing, bar)
	// Run the processing pipeline.
	return s.runPipeline(ctx, input, output)
}

// runPipeline runs the processing pipeline.
func (s *streamProcessor) runPipeline(ctx context.Context, input io.Reader, output io.Writer) error {
	pipelineCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// Read chunks from the input stream.
	tasks, readerErr := s.reader.ReadChunks(pipelineCtx, input)
	// Process the chunks in a worker pool.
	results := s.pool.Process(pipelineCtx, tasks)

	var writerErr error
	var wg sync.WaitGroup

	// Write the results to the output stream.
	wg.Go(func() {
		writerErr = s.writer.WriteChunks(pipelineCtx, output, results)
	})

	wg.Wait()
	// Check for any errors from the reader.
	select {
	case err := <-readerErr:
		if err != nil {
			cancel()
			return fmt.Errorf("reader error: %w", err)
		}
	default:
	}

	// Check for any errors from the writer.
	if writerErr != nil {
		cancel()
		return fmt.Errorf("writer error: %w", writerErr)
	}

	// Check if the operation was canceled.
	if pipelineCtx.Err() != nil {
		return fmt.Errorf("operation was canceled: %w", pipelineCtx.Err())
	}

	return nil
}
