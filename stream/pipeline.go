package stream

import (
	"context"
	"fmt"
	"io"
	"runtime"

	"github.com/hambosto/sweetbyte/derive"
	"github.com/hambosto/sweetbyte/types"
	"github.com/hambosto/sweetbyte/ui"
	"golang.org/x/sync/errgroup"
)

const (
	// DefaultChunkSize specifies the default size for data chunks in bytes (256KB)
	DefaultChunkSize = 256 * 1024
)

// Pipeline orchestrates the entire streaming process by coordinating
// chunk reading, processing, and writing operations in a concurrent pipeline.
type Pipeline struct {
	key           []byte           // The encryption/decryption key
	processing    types.Processing // The type of processing (encryption/decryption)
	concurrency   int              // Number of concurrent worker goroutines
	chunkSize     int              // Size of each data chunk
	taskProcessor *TaskProcessor   // Processor for individual tasks
	reader        *ChunkReader     // Reader for input chunks
	pool          *WorkerPool      // Pool of workers for concurrent processing
}

// NewPipeline creates and returns a new Pipeline instance with the specified key
// and processing type. It validates the key length and initializes all required
// components for the streaming pipeline.
func NewPipeline(key []byte, processing types.Processing) (*Pipeline, error) {
	// Validate key length against Argon key length requirement
	if len(key) != derive.ArgonKeyLen {
		return nil, fmt.Errorf("key must be %d bytes long", derive.ArgonKeyLen)
	}

	// Create the task processor for handling individual chunks
	taskProcessor, err := NewTaskProcessor(key, processing)
	if err != nil {
		return nil, fmt.Errorf("failed to create task processor: %w", err)
	}

	// Determine concurrency based on available CPU cores
	concurrency := runtime.NumCPU()
	return &Pipeline{
		key:           key,                                                       // Set the encryption/decryption key
		processing:    processing,                                                // Set the processing type
		concurrency:   concurrency,                                               // Set the concurrency level
		chunkSize:     DefaultChunkSize,                                          // Set default chunk size
		taskProcessor: taskProcessor,                                             // Set the task processor
		reader:        NewChunkReader(processing, DefaultChunkSize, concurrency), // Set the chunk reader
		pool:          NewWorkerPool(taskProcessor, concurrency),                 // Set the worker pool
	}, nil
}

// Process executes the complete streaming pipeline by reading from the input,
// processing chunks concurrently, and writing the results to the output.
// It also manages progress reporting during the operation.
func (p *Pipeline) Process(ctx context.Context, input io.Reader, output io.Writer, totalSize int64) error {
	// Validate input and output streams
	if input == nil || output == nil {
		return fmt.Errorf("input and output streams must not be nil")
	}

	// Create a progress bar for visual feedback
	bar := ui.NewProgressBar(totalSize, p.processing.String())
	// Create a chunk writer with the progress bar
	writer := NewChunkWriter(p.processing, bar)

	// Run the complete pipeline operation
	return p.runPipeline(ctx, input, output, writer)
}

// runPipeline executes the core pipeline operation coordinating the reading,
// processing, and writing of data chunks using errgroup for error handling.
func (p *Pipeline) runPipeline(ctx context.Context, input io.Reader, output io.Writer, writer *ChunkWriter) error {
	// Create an errgroup to manage goroutines and collect errors
	g, ctx := errgroup.WithContext(ctx)

	// Start reading chunks from input, getting tasks and error channels
	tasks, readerErr := p.reader.ReadChunks(ctx, input)

	// Process tasks through the worker pool
	results := p.pool.Process(ctx, tasks)

	// Start the writer goroutine to write processed results to output
	g.Go(func() error {
		return writer.WriteChunks(ctx, output, results)
	})

	// Start the reader error handler goroutine to propagate read errors
	g.Go(func() error {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-readerErr:
			return err
		}
	})

	// Wait for all goroutines to complete and return any error
	return g.Wait()
}
