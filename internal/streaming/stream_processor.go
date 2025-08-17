// Package streaming provides the infrastructure for efficient, chunk-based file processing.
// It includes components for reading, processing, and writing data in a streaming fashion,
// utilizing concurrency for performance and managing the order of processed chunks.
package streaming

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/hambosto/sweetbyte/internal/ui"
)

// Task represents a unit of work to be processed by the streaming pipeline.
// Each task contains a chunk of data and its original index.
type Task struct {
	Data  []byte // The raw or encrypted data chunk.
	Index uint64 // The sequential index of this chunk in the original file.
}

// TaskResult represents the outcome of processing a Task.
// It includes the processed data, its original index, size, and any error encountered.
type TaskResult struct {
	Index uint64 // The sequential index of the processed chunk.
	Data  []byte // The processed (encrypted/decrypted) data chunk.
	Size  int    // The size of the processed data.
	Err   error  // Any error that occurred during processing this task.
}

// streamProcessor implements the Processor interface and orchestrates the entire
// streaming encryption/decryption pipeline. It manages the flow of data chunks
// through readers, worker pools, and writers.
type streamProcessor struct {
	streamConfig  StreamConfig  // Configuration for the streaming process (e.g., key, processing mode).
	taskProcessor TaskProcessor // The actual logic for encrypting/decrypting individual chunks.
	reader        ChunkReader   // Component responsible for reading chunks from the input stream.
	writer        ChunkWriter   // Component responsible for writing processed chunks to the output stream.
	pool          *workerPool   // The worker pool managing concurrent task processing.
}

// NewStreamProcessor creates and returns a new Processor instance.
// It initializes the stream processing components based on the provided StreamConfig.
// It validates the configuration and sets up the underlying task processor, chunk reader, and worker pool.
func NewStreamProcessor(config StreamConfig) (Processor, error) {
	if err := config.Validate(); err != nil {
		return nil, err // Return error if configuration is invalid.
	}
	config.ApplyDefaults() // Apply default values to configuration if not explicitly set.

	// Initialize the task processor responsible for the actual encryption/decryption work on chunks.
	taskProcessor, err := NewTaskProcessor(config.Key, config.Processing)
	if err != nil {
		return nil, fmt.Errorf("failed to create task processor: %w", err) // Propagate error if task processor creation fails.
	}

	// Return a new streamProcessor with initialized components.
	return &streamProcessor{
		streamConfig:  config,                                              // Store the validated stream configuration.
		taskProcessor: taskProcessor,                                       // Assign the created task processor.
		reader:        NewChunkReader(config.Processing, config.ChunkSize), // Initialize a new chunk reader.
		pool:          NewWorkerPool(taskProcessor, config.Concurrency),    // Initialize a new worker pool.
	}, nil
}

// Process orchestrates the streaming operation from input to output.
// It sets up a progress bar and then initiates the concurrent pipeline
// of reading, processing, and writing data chunks.
func (s *streamProcessor) Process(ctx context.Context, input io.Reader, output io.Writer, totalSize int64) error {
	if input == nil || output == nil {
		return fmt.Errorf("input and output streams must not be nil") // Validate input/output streams.
	}

	// Initialize a progress bar for visual feedback during the operation.
	bar := ui.NewProgressBar(totalSize, s.streamConfig.Processing.String())
	s.writer = NewChunkWriter(s.streamConfig.Processing, bar) // Initialize the chunk writer with the progress bar.

	// Run the main processing pipeline.
	return s.runPipeline(ctx, input, output)
}

// runPipeline manages the concurrent execution of reading, processing, and writing chunks.
// It sets up goroutines for each stage and handles error propagation and context cancellation.
func (s *streamProcessor) runPipeline(ctx context.Context, input io.Reader, output io.Writer) error {
	pipelineCtx, cancel := context.WithCancel(ctx)
	defer cancel() // Ensure cancellation function is called to release resources.

	// Start reading chunks from the input stream in a separate goroutine.
	tasks, readerErr := s.reader.ReadChunks(pipelineCtx, input)
	// Start processing tasks using the worker pool in separate goroutines.
	results := s.pool.Process(pipelineCtx, tasks)

	var writerErr error
	var wg sync.WaitGroup // WaitGroup to ensure the writer goroutine completes.

	// Add one goroutine to the WaitGroup for the writer.
	wg.Add(1)
	// Start writing processed chunks to the output stream in a separate goroutine.
	go func() {
		defer wg.Done()                                                // Signal completion when the goroutine finishes.
		writerErr = s.writer.WriteChunks(pipelineCtx, output, results) // Write chunks and capture any error.
	}()
	wg.Wait() // Wait for the writer goroutine to complete.

	// Check for errors from the reader goroutine.
	select {
	case err := <-readerErr:
		if err != nil {
			cancel()                                   // Cancel the pipeline context on reader error.
			return fmt.Errorf("reader error: %w", err) // Return reader error.
		}
	default:
		// No reader error yet or reader channel is empty.
	}

	// Check for errors from the writer goroutine.
	if writerErr != nil {
		cancel()                                         // Cancel the pipeline context on writer error.
		return fmt.Errorf("writer error: %w", writerErr) // Return writer error.
	}

	// Check if the pipeline context was cancelled due to an external signal or error.
	if pipelineCtx.Err() != nil {
		return fmt.Errorf("operation was canceled: %w", pipelineCtx.Err()) // Return context cancellation error.
	}

	return nil // Return nil if the pipeline completes successfully.
}
