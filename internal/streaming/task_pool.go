package streaming

import (
	"context"
	"fmt"

	"github.com/hambosto/sweetbyte/internal/options"
	"github.com/hambosto/sweetbyte/internal/processor"
)

// taskProcessor adapts the in-memory `processor.Processor` to operate on
// chunked tasks. It does not manage ordering or I/O; it only transforms bytes
// according to the selected `options.Processing` mode.
type taskProcessor struct {
	processor  *processor.Processor
	processing options.Processing
}

// NewTaskProcessor creates a new task processor with the given master `key`
// and processing mode (encryption/decryption). The underlying `processor`
// performs the actual pipeline (compress/pad/cipher/encode).
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

// Process transforms one chunk based on the configured mode.
// Cancellation via `ctx` aborts processing and returns the context error.
// The Size field in the returned `TaskResult` is used by the progress bar.
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

// calculateProgressSize determines the amount to add to the progress bar for
// a single processed chunk. For encryption, we report input bytes; for
// decryption, we report output bytes since ciphertext sizes include framing.
func (tp *taskProcessor) calculateProgressSize(input, output []byte) int {
	if tp.processing == options.Encryption {
		return len(input) // Track input size for encryption
	}
	return len(output) // Track output size for decryption
}
