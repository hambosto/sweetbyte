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

// chunkWriter writes processed `TaskResult`s to the output in order.
//
// Behavior by mode:
//   - Encryption: emits a 4-byte big-endian size header before each chunk.
//   - Decryption: writes raw plaintext data without a size header.
//
// Ordering is ensured via `OrderBuffer`, which buffers out-of-order results
// until their predecessors arrive. An optional progress bar is advanced by the
// logical size of each result (see `taskProcessor.calculateProgressSize`).
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

// WriteChunks consumes results from `results` and writes them to `output` in
// order. It honors context cancellation and returns the first error encountered.
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

// flushRemaining drains the order buffer and writes any remaining results.
func (w *chunkWriter) flushRemaining(output io.Writer) error {
	remaining := w.buffer.Flush()
	return w.writeResults(output, remaining)
}

// writeResults writes a batch of ready results to `output`.
func (w *chunkWriter) writeResults(output io.Writer, results []TaskResult) error {
	for _, result := range results {
		if err := w.writeResult(output, result); err != nil {
			return err
		}
	}
	return nil
}

// writeResult writes a single result to `output`.
// For encryption mode, a 4-byte big-endian chunk length header is written
// prior to the data payload.
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

// writeChunkSize encodes `size` as a 4-byte big-endian unsigned integer and
// writes it to `output`. Guards against negative sizes and values exceeding
// uint32 to prevent overflow downstream.
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
