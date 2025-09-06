// Package streaming provides functionalities for streaming data processing.
package streaming

import (
	"context"
	"fmt"

	"github.com/hambosto/sweetbyte/internal/options"
	"github.com/hambosto/sweetbyte/internal/processor"
)

// TaskProcessor defines the interface for processing a task.
type TaskProcessor interface {
	// Process processes a single task.
	Process(ctx context.Context, task Task) TaskResult
}

// taskProcessor implements the TaskProcessor interface.
type taskProcessor struct {
	processor  processor.Processor
	processing options.Processing
}

// NewTaskProcessor creates a new TaskProcessor.
func NewTaskProcessor(key []byte, processing options.Processing) (TaskProcessor, error) {
	// Create a new data processor.
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
	// Check for cancellation.
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

	// Process the task based on the processing type.
	switch tp.processing {
	case options.Encryption:
		output, err = tp.processor.Encrypt(task.Data)
	case options.Decryption:
		output, err = tp.processor.Decrypt(task.Data)
	default:
		err = fmt.Errorf("unknown processing type: %d", tp.processing)
	}

	// Calculate the size for the progress bar.
	size := tp.calculateProgressSize(task.Data, output)
	return TaskResult{
		Index: task.Index,
		Data:  output,
		Size:  size,
		Err:   err,
	}
}

// calculateProgressSize calculates the size for the progress bar.
func (tp *taskProcessor) calculateProgressSize(input, output []byte) int {
	if tp.processing == options.Encryption {
		return len(input)
	}
	return len(output)
}
