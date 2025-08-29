// Package streaming provides the core functionality for streaming encryption and decryption.
package streaming

import (
	"context"
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/options"
	"github.com/hambosto/sweetbyte/internal/ui"
	"github.com/hambosto/sweetbyte/internal/utils"
)

// chunkWriter writes processed chunks to an io.Writer.
// It uses an OrderBuffer to ensure chunks are written in the correct sequence.
type chunkWriter struct {
	processing options.Processing
	buffer     *orderBuffer
	bar        *ui.ProgressBar
}

// NewChunkWriter creates a new ChunkWriter.
// It takes the processing mode (encryption/decryption) and an optional progress bar.
func NewChunkWriter(processing options.Processing, bar *ui.ProgressBar) *chunkWriter {
	return &chunkWriter{
		processing: processing,
		buffer:     NewOrderBuffer(),
		bar:        bar,
	}
}

// WriteChunks receives processed task results from a channel and writes them to the output writer.
// It ensures that chunks are written in the correct order.
func (w *chunkWriter) WriteChunks(ctx context.Context, output io.Writer, results <-chan TaskResult) error {
	for {
		select {
		case result, ok := <-results:
			// If the results channel is closed, flush any remaining buffered chunks and exit.
			if !ok {
				return w.flushRemaining(output)
			}

			// If a task resulted in an error, return it immediately.
			if result.Err != nil {
				return fmt.Errorf("processing chunk %d: %w", result.Index, result.Err)
			}

			// Add the result to the buffer and get any chunks that are now ready to be written.
			ready := w.buffer.Add(result)
			if err := w.writeResults(output, ready); err != nil {
				return err
			}
		case <-ctx.Done():
			// If the context is canceled, return the context error.
			return ctx.Err()
		}
	}
}

// flushRemaining writes any chunks that are still in the buffer to the output.
func (w *chunkWriter) flushRemaining(output io.Writer) error {
	remaining := w.buffer.Flush()
	return w.writeResults(output, remaining)
}

// writeResults iterates over a slice of task results and writes them to the output.
func (w *chunkWriter) writeResults(output io.Writer, results []TaskResult) error {
	for _, result := range results {
		if err := w.writeResult(output, result); err != nil {
			return err
		}
	}
	return nil
}

// writeResult writes a single task result to the output.
// For encryption, it prepends the chunk data with its size.
func (w *chunkWriter) writeResult(output io.Writer, result TaskResult) error {
	// For encryption, write the chunk size as a header before the data.
	if w.processing == options.Encryption {
		if err := w.writeChunkSize(output, len(result.Data)); err != nil {
			return fmt.Errorf("writing chunk size: %w", err)
		}
	}

	// Write the actual chunk data.
	if _, err := output.Write(result.Data); err != nil {
		return fmt.Errorf("writing chunk data: %w", err)
	}

	// If a progress bar is configured, update it with the size of the written chunk.
	if w.bar != nil {
		if err := w.bar.Add(int64(result.Size)); err != nil {
			return fmt.Errorf("updating progress: %w", err)
		}
	}

	return nil
}

// writeChunkSize writes the size of a chunk as a 4-byte header to the output.
func (w *chunkWriter) writeChunkSize(output io.Writer, size int) error {
	// #nosec G115
	buffer := utils.ToBytes(uint32(size))
	if _, err := output.Write(buffer); err != nil {
		return fmt.Errorf("chunk size write failed: %w", err)
	}

	return nil
}
