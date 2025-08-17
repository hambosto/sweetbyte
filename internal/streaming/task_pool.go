// Package streaming defines the interfaces and core components for efficient, chunk-based file processing.
// It provides a flexible architecture for handling large files through concurrent operations.
package streaming

import (
	"context"
	"fmt"

	"github.com/hambosto/sweetbyte/internal/options"
	"github.com/hambosto/sweetbyte/internal/processor"
)

// taskProcessor implements the TaskProcessor interface.
// It is responsible for applying the core encryption or decryption logic
// to individual data chunks using an underlying `processor.Processor`.
type taskProcessor struct {
	processor  *processor.Processor // The core processor that performs cryptographic operations.
	processing options.Processing   // The type of operation (encryption or decryption) this task processor performs.
}

// NewTaskProcessor creates and returns a new TaskProcessor instance.
// It initializes the underlying `processor.Processor` with the provided key.
// Returns an error if the `processor.Processor` fails to initialize.
func NewTaskProcessor(key []byte, processing options.Processing) (TaskProcessor, error) {
	proc, err := processor.NewProcessor(key) // Create a new core processor with the given key.
	if err != nil {
		return nil, fmt.Errorf("failed to create processor: %w", err) // Propagate error if processor creation fails.
	}

	return &taskProcessor{
		processor:  proc,       // Assign the initialized core processor.
		processing: processing, // Set the processing type.
	}, nil
}

// Process applies the configured cryptographic operation (encryption or decryption)
// to a single data `Task` and returns a `TaskResult`.
// It checks for context cancellation before processing.
func (tp *taskProcessor) Process(ctx context.Context, task Task) TaskResult {
	select {
	case <-ctx.Done(): // Check if the context has been cancelled.
		return TaskResult{
			Index: task.Index, // Preserve the original task index.
			Err:   ctx.Err(),  // Return the context cancellation error.
		}
	default:
		// Continue if context is not cancelled.
	}

	var output []byte // Variable to store the processed data.
	var err error     // Variable to store any error during processing.

	switch tp.processing {
	case options.Encryption: // If the operation is encryption.
		output, err = tp.processor.Encrypt(task.Data) // Encrypt the task data.
	case options.Decryption: // If the operation is decryption.
		output, err = tp.processor.Decrypt(task.Data) // Decrypt the task data.
	default:
		err = fmt.Errorf("unknown processing type: %d", tp.processing) // Handle unknown processing types.
	}

	size := tp.calculateProgressSize(task.Data, output) // Calculate the size for progress reporting.

	return TaskResult{
		Index: task.Index, // Return the original task index.
		Data:  output,     // Return the processed data.
		Size:  size,       // Return the size for progress updates.
		Err:   err,        // Return any error encountered during processing.
	}
}

// calculateProgressSize determines the size to report for progress updates.
// For encryption, it uses the input data size (before expansion). For decryption, it uses the output data size.
func (tp *taskProcessor) calculateProgressSize(input, output []byte) int {
	if tp.processing == options.Encryption { // If encrypting, progress is based on original input size.
		return len(input)
	}
	return len(output) // If decrypting, progress is based on the size of the decrypted output.
}
