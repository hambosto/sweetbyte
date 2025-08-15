package streaming

import (
	"context"
	"fmt"
	"io"
	"runtime"
	"sync"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/errors"
	"github.com/hambosto/sweetbyte/internal/types"
	"github.com/hambosto/sweetbyte/internal/ui"
)

// Config holds stream processing configuration
type Config struct {
	Key         []byte
	Processing  types.Processing
	Concurrency int
	ChunkSize   int
}

// Validate validates the stream configuration
func (c *Config) Validate() error {
	if len(c.Key) != config.MasterKeySize {
		return errors.ErrInvalidKey
	}
	return nil
}

// ApplyDefaults applies default values to unset configuration fields
func (c *Config) ApplyDefaults() {
	if c.Concurrency <= 0 {
		c.Concurrency = runtime.NumCPU()
	}
	if c.ChunkSize <= 0 {
		c.ChunkSize = config.DefaultChunkSize
	}
}

// streamProcessor is the main streaming processor implementation
type streamProcessor struct {
	config        Config
	taskProcessor TaskProcessor
	reader        ChunkReader
	writer        ChunkWriter
	pool          *workerPool
}

// NewStreamProcessor creates a new streaming processor
func NewStreamProcessor(config Config) (Processor, error) {
	if err := config.Validate(); err != nil {
		return nil, err
	}

	config.ApplyDefaults()

	taskProcessor, err := NewTaskProcessor(config.Key, config.Processing)
	if err != nil {
		return nil, fmt.Errorf("failed to create task processor: %w", err)
	}

	return &streamProcessor{
		config:        config,
		taskProcessor: taskProcessor,
		reader:        NewChunkReader(config.Processing, config.ChunkSize),
		pool:          NewWorkerPool(taskProcessor, config.Concurrency),
	}, nil
}

// Process processes data from input to output
func (s *streamProcessor) Process(ctx context.Context, input io.Reader, output io.Writer, totalSize int64) error {
	if input == nil || output == nil {
		return errors.ErrNilStream
	}

	// Create progress bar
	bar := ui.NewProgressBar(totalSize, s.config.Processing.String())
	s.writer = NewChunkWriter(s.config.Processing, bar)

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
		return errors.ErrCanceled
	}

	return nil
}
