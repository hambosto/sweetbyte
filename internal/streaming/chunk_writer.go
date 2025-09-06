// Package streaming provides functionalities for streaming data processing.
package streaming

import (
	"context"
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/options"
	"github.com/hambosto/sweetbyte/internal/ui"
	"github.com/hambosto/sweetbyte/internal/utils"
)

// ChunkWriter defines the interface for writing chunks to an output stream.
type ChunkWriter interface {
	// WriteChunks writes chunks from a channel to the output stream.
	WriteChunks(ctx context.Context, output io.Writer, results <-chan TaskResult) error
}

// chunkWriter implements the ChunkWriter interface.
type chunkWriter struct {
	processing options.Processing
	buffer     OrderBuffer
	bar        ui.ProgressBar
}

// NewChunkWriter creates a new ChunkWriter.
func NewChunkWriter(processing options.Processing, bar ui.ProgressBar) ChunkWriter {
	return &chunkWriter{
		processing: processing,
		buffer:     NewOrderBuffer(),
		bar:        bar,
	}
}

// WriteChunks writes chunks from a channel to the output stream.
func (w *chunkWriter) WriteChunks(ctx context.Context, output io.Writer, results <-chan TaskResult) error {
	for {
		select {
		case result, ok := <-results:
			// If the channel is closed, flush the remaining results and return.
			if !ok {
				return w.flushRemaining(output)
			}

			// If there was an error processing the chunk, return it.
			if result.Err != nil {
				return fmt.Errorf("processing chunk %d: %w", result.Index, result.Err)
			}

			// Add the result to the order buffer and write any ready results.
			ready := w.buffer.Add(result)
			if err := w.writeResults(output, ready); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// flushRemaining flushes any remaining results in the order buffer.
func (w *chunkWriter) flushRemaining(output io.Writer) error {
	remaining := w.buffer.Flush()
	return w.writeResults(output, remaining)
}

// writeResults writes a slice of task results to the output stream.
func (w *chunkWriter) writeResults(output io.Writer, results []TaskResult) error {
	for _, result := range results {
		if err := w.writeResult(output, result); err != nil {
			return err
		}
	}
	return nil
}

// writeResult writes a single task result to the output stream.
func (w *chunkWriter) writeResult(output io.Writer, result TaskResult) error {
	// If encrypting, write the chunk size before the data.
	if w.processing == options.Encryption {
		if err := w.writeChunkSize(output, len(result.Data)); err != nil {
			return fmt.Errorf("writing chunk size: %w", err)
		}
	}

	// Write the chunk data.
	if _, err := output.Write(result.Data); err != nil {
		return fmt.Errorf("writing chunk data: %w", err)
	}

	// Update the progress bar.
	if w.bar != nil {
		if err := w.bar.Add(int64(result.Size)); err != nil {
			return fmt.Errorf("updating progress: %w", err)
		}
	}

	return nil
}

// writeChunkSize writes the size of a chunk to the output stream.
func (w *chunkWriter) writeChunkSize(output io.Writer, size int) error {
	// #nosec G115
	buffer := utils.ToBytes(uint32(size))
	if _, err := output.Write(buffer); err != nil {
		return fmt.Errorf("chunk size write failed: %w", err)
	}

	return nil
}
