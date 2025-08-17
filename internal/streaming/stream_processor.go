package streaming

import (
	"context"
	"fmt"
	"io"
	"sync"

	"github.com/hambosto/sweetbyte/internal/ui"
)

type Task struct {
	Data  []byte
	Index uint64
}

type TaskResult struct {
	Index uint64
	Data  []byte
	Size  int
	Err   error
}

type streamProcessor struct {
	streamConfig  StreamConfig
	taskProcessor TaskProcessor
	reader        ChunkReader
	writer        ChunkWriter
	pool          *workerPool
}

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

func (s *streamProcessor) Process(ctx context.Context, input io.Reader, output io.Writer, totalSize int64) error {
	if input == nil || output == nil {
		return fmt.Errorf("input and output streams must not be nil")
	}

	bar := ui.NewProgressBar(totalSize, s.streamConfig.Processing.String())
	s.writer = NewChunkWriter(s.streamConfig.Processing, bar)

	return s.runPipeline(ctx, input, output)
}

func (s *streamProcessor) runPipeline(ctx context.Context, input io.Reader, output io.Writer) error {
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
