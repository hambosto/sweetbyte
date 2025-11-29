package stream

import (
	"context"
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/types"
	"github.com/hambosto/sweetbyte/ui"
	"github.com/hambosto/sweetbyte/utils"
)

// ChunkWriter handles writing processed chunks to the output.
// It manages the ordered buffer to ensure chunks are written in the correct sequence
// and updates progress bars during the process.
type ChunkWriter struct {
	processing types.Processing // The type of processing (encryption/decryption) being performed
	buffer     *OrderedBuffer   // Buffer to maintain correct order of chunks
	bar        *ui.ProgressBar  // Progress bar for visual feedback
}

// NewChunkWriter creates and returns a new ChunkWriter instance with the specified
// processing type and progress bar.
func NewChunkWriter(processing types.Processing, bar *ui.ProgressBar) *ChunkWriter {
	return &ChunkWriter{
		processing: processing,         // Set the processing type
		buffer:     NewOrderedBuffer(), // Initialize ordered buffer for maintaining chunk order
		bar:        bar,                // Progress bar for status updates
	}
}

// WriteChunks processes task results and writes them to the output in the correct order.
// It maintains an ordered buffer to ensure chunks are written sequentially despite
// potentially out-of-order processing.
func (w *ChunkWriter) WriteChunks(ctx context.Context, output io.Writer, results <-chan types.TaskResult) error {
	for {
		// Check if context has been cancelled
		select {
		case <-ctx.Done():
			return ctx.Err()
		case result, ok := <-results:
			if !ok {
				// Channel closed, flush remaining results from buffer
				return w.writeResults(output, w.buffer.Flush())
			}

			if result.Err != nil {
				// Return error if a task failed
				return fmt.Errorf("task %d failed: %w", result.Index, result.Err)
			}

			// Add result to buffer and get ready-to-write results
			ready := w.buffer.Add(result)
			// Write any ready results to output
			if err := w.writeResults(output, ready); err != nil {
				return err
			}
		}
	}
}

// writeResults writes the processed results to the output writer.
// For encryption, it writes chunk size headers followed by the data.
// For decryption, it writes the data directly.
// It also updates the progress bar as data is written.
func (w *ChunkWriter) writeResults(output io.Writer, results []types.TaskResult) error {
	for _, res := range results {
		// For encryption mode, write the size header before the data
		if w.processing == types.Encryption {
			// Convert data length to bytes for size header
			sizeBytes := utils.ToBytes(uint32(len(res.Data)))
			if _, err := output.Write(sizeBytes); err != nil {
				return fmt.Errorf("writing chunk size: %w", err)
			}
		}

		// Write the actual data
		if _, err := output.Write(res.Data); err != nil {
			return fmt.Errorf("writing chunk data: %w", err)
		}

		// Update progress bar with the processed size
		if err := w.bar.Add(int64(res.Size)); err != nil {
			return fmt.Errorf("updating progress: %w", err)
		}
	}
	return nil
}
