package streaming

import (
	"context"
	"fmt"

	"github.com/hambosto/sweetbyte/internal/options"
	"github.com/hambosto/sweetbyte/internal/processor"
)

// taskProcessor handles the actual encryption/decryption of individual chunks
type taskProcessor struct {
	processor  *processor.Processor
	processing options.Processing
}

// NewTaskProcessor creates a new task processor
func NewTaskProcessor(key []byte, processing options.Processing) (TaskProcessor, error) {
	proc, err := processor.NewProcessor(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create processor: %w", err)
	}

	return &taskProcessor{
		processor:  proc,
		processing: processing,
	}, nil
}

// Process processes a single chunk based on the operation type
func (tp *taskProcessor) Process(ctx context.Context, task Task) TaskResult {
	select {
	case <-ctx.Done():
		return TaskResult{
			Index: task.Index,
			Err:   ctx.Err(),
		}
	default:
	}

	var output []byte
	var err error

	switch tp.processing {
	case options.Encryption:
		output, err = tp.processor.Encrypt(task.Data)
	case options.Decryption:
		output, err = tp.processor.Decrypt(task.Data)
	default:
		err = fmt.Errorf("unknown processing type: %d", tp.processing)
	}

	size := tp.calculateProgressSize(task.Data, output)

	return TaskResult{
		Index: task.Index,
		Data:  output,
		Size:  size,
		Err:   err,
	}
}

// calculateProgressSize determines the size to use for progress tracking
func (tp *taskProcessor) calculateProgressSize(input, output []byte) int {
	if tp.processing == options.Encryption {
		return len(input) // Track input size for encryption
	}
	return len(output) // Track output size for decryption
}
