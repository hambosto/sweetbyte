// Package streaming provides the core functionality for streaming encryption and decryption.
package streaming

import (
	"context"
	"fmt"

	"github.com/hambosto/sweetbyte/internal/options"
	"github.com/hambosto/sweetbyte/internal/processor"
)

// TaskProcessor processes individual tasks (chunks of data).
type TaskProcessor interface {
	Process(ctx context.Context, task Task) TaskResult
}

// taskProcessor processes individual tasks (chunks of data).
type taskProcessor struct {
	processor  processor.Processor
	processing options.Processing
}

// NewTaskProcessor creates a new TaskProcessor with the given key and processing type.
func NewTaskProcessor(key []byte, processing options.Processing) (TaskProcessor, error) {
	// Create a new processor.
	proc, err := processor.NewProcessor(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create processor: %w", err)
	}

	return &taskProcessor{
		processor:  proc,
		processing: processing,
	}, nil
}

// Process processes a single task.
func (tp *taskProcessor) Process(ctx context.Context, task Task) TaskResult {
	// Check if the context has been canceled.
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

	// Perform the appropriate action based on the processing type.
	switch tp.processing {
	case options.Encryption:
		output, err = tp.processor.Encrypt(task.Data)
	case options.Decryption:
		output, err = tp.processor.Decrypt(task.Data)
	default:
		err = fmt.Errorf("unknown processing type: %d", tp.processing)
	}

	// Calculate the size for progress reporting.
	size := tp.calculateProgressSize(task.Data, output)
	return TaskResult{
		Index: task.Index,
		Data:  output,
		Size:  size,
		Err:   err,
	}
}

// calculateProgressSize calculates the size of the data to be reported for progress.
// For encryption, it's the input size; for decryption, it's the output size.
func (tp *taskProcessor) calculateProgressSize(input, output []byte) int {
	if tp.processing == options.Encryption {
		return len(input)
	}
	return len(output)
}
