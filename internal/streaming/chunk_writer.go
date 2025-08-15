package streaming

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"math"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/options"
	"github.com/hambosto/sweetbyte/internal/ui"
)

// chunkWriter handles writing processed chunks to output
type chunkWriter struct {
	processing options.Processing
	buffer     OrderBuffer
	bar        *ui.ProgressBar
}

// NewChunkWriter creates a new chunk writer
func NewChunkWriter(processing options.Processing, bar *ui.ProgressBar) ChunkWriter {
	return &chunkWriter{
		processing: processing,
		buffer:     NewOrderBuffer(),
		bar:        bar,
	}
}

// WriteChunks writes processed chunks to output in order
func (w *chunkWriter) WriteChunks(ctx context.Context, output io.Writer, results <-chan TaskResult) error {
	for {
		select {
		case result, ok := <-results:
			if !ok {
				// Channel closed, flush remaining results
				return w.flushRemaining(output)
			}

			if result.Err != nil {
				return fmt.Errorf("processing chunk %d: %w", result.Index, result.Err)
			}

			ready := w.buffer.Add(result)
			if err := w.writeResults(output, ready); err != nil {
				return err
			}

		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// flushRemaining writes any remaining buffered results
func (w *chunkWriter) flushRemaining(output io.Writer) error {
	remaining := w.buffer.Flush()
	return w.writeResults(output, remaining)
}

// writeResults writes a slice of ready results
func (w *chunkWriter) writeResults(output io.Writer, results []TaskResult) error {
	for _, result := range results {
		if err := w.writeResult(output, result); err != nil {
			return err
		}
	}
	return nil
}

// writeResult writes a single result to the output
func (w *chunkWriter) writeResult(output io.Writer, result TaskResult) error {
	// Write chunk size header for encryption
	if w.processing == options.Encryption {
		if err := w.writeChunkSize(output, len(result.Data)); err != nil {
			return fmt.Errorf("writing chunk size: %w", err)
		}
	}

	// Write chunk data
	if _, err := output.Write(result.Data); err != nil {
		return fmt.Errorf("writing chunk data: %w", err)
	}

	// Update progress bar
	if w.bar != nil {
		if err := w.bar.Add(int64(result.Size)); err != nil {
			return fmt.Errorf("updating progress: %w", err)
		}
	}

	return nil
}

// writeChunkSize writes the chunk size as a 4-byte big-endian integer
func (w *chunkWriter) writeChunkSize(output io.Writer, size int) error {
	if size < 0 || size > math.MaxUint32 {
		return fmt.Errorf("chunk size out of range: %d", size)
	}

	var buffer [config.ChunkHeaderSize]byte
	binary.BigEndian.PutUint32(buffer[:], uint32(size))

	if _, err := output.Write(buffer[:]); err != nil {
		return fmt.Errorf("chunk size write failed: %w", err)
	}
	return nil
}
