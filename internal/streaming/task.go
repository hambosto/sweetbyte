package streaming

import (
	"context"
	"fmt"

	"github.com/hambosto/sweetbyte/internal/processor"
	"github.com/hambosto/sweetbyte/internal/types"
)

// taskProcessor handles the actual encryption/decryption of individual chunks
type taskProcessor struct {
	processor  *processor.Processor
	processing types.Processing
}

// NewTaskProcessor creates a new task processor
func NewTaskProcessor(key []byte, processing types.Processing) (TaskProcessor, error) {
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
func (tp *taskProcessor) Process(ctx context.Context, task types.Task) types.TaskResult {
	select {
	case <-ctx.Done():
		return types.TaskResult{
			Index: task.Index,
			Err:   ctx.Err(),
		}
	default:
	}

	var output []byte
	var err error

	switch tp.processing {
	case types.Encryption:
		output, err = tp.processor.Encrypt(task.Data)
	case types.Decryption:
		output, err = tp.processor.Decrypt(task.Data)
	default:
		err = fmt.Errorf("unknown processing type: %d", tp.processing)
	}

	size := tp.calculateProgressSize(task.Data, output)

	return types.TaskResult{
		Index: task.Index,
		Data:  output,
		Size:  size,
		Err:   err,
	}
}

// calculateProgressSize determines the size to use for progress tracking
func (tp *taskProcessor) calculateProgressSize(input, output []byte) int {
	if tp.processing == types.Encryption {
		return len(input) // Track input size for encryption
	}
	return len(output) // Track output size for decryption
}
