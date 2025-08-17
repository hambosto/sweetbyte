// Package streaming provides the infrastructure for efficient, chunk-based file processing.
// It includes components for reading, processing, and writing data in a streaming fashion,
// utilizing concurrency for performance and managing the order of processed chunks.
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

// chunkWriter implements the ChunkWriter interface.
// It is responsible for writing processed data chunks to an output stream,
// ensuring they are written in the correct order using an internal buffer and updating a progress bar.
type chunkWriter struct {
	processing options.Processing // The type of processing (encryption or decryption) to guide writing behavior (e.g., adding length prefixes).
	buffer     OrderBuffer        // An internal buffer to maintain the correct order of chunks before writing.
	bar        *ui.ProgressBar    // A progress bar to update the user on the writing progress.
}

// NewChunkWriter creates and returns a new ChunkWriter instance.
// It initializes the writer with the specified processing type, an order buffer, and a progress bar.
func NewChunkWriter(processing options.Processing, bar *ui.ProgressBar) ChunkWriter {
	return &chunkWriter{
		processing: processing,       // Set the processing type.
		buffer:     NewOrderBuffer(), // Initialize a new order buffer to handle out-of-order results.
		bar:        bar,              // Assign the progress bar for updates.
	}
}

// WriteChunks reads processed TaskResults from a channel and writes them to the output stream.
// It uses an internal buffer to ensure chunks are written in their original sequential order.
// It also handles errors from processing and context cancellation.
func (w *chunkWriter) WriteChunks(ctx context.Context, output io.Writer, results <-chan TaskResult) error {
	for { // Loop indefinitely to receive results until the channel is closed or context is cancelled.
		select {
		case result, ok := <-results: // Receive a processed TaskResult from the channel.

			if !ok { // If the channel is closed, flush any remaining buffered results and exit.
				return w.flushRemaining(output)
			}

			if result.Err != nil { // If the received result indicates an error during processing.
				return fmt.Errorf("processing chunk %d: %w", result.Index, result.Err) // Return the processing error.
			}

			ready := w.buffer.Add(result) // Add the result to the order buffer; get any chunks that are now in order.

			if err := w.writeResults(output, ready); err != nil { // Write the now-in-order chunks to the output.
				return err // Propagate any error during writing.
			}

		case <-ctx.Done(): // If the context is cancelled, stop writing and return the context error.

			return ctx.Err()
		}
	}
}

// flushRemaining writes any remaining buffered chunks to the output when the results channel is closed.
// This ensures all processed data is written, even if the stream ends before all chunks are received.
func (w *chunkWriter) flushRemaining(output io.Writer) error {
	remaining := w.buffer.Flush()            // Get all remaining chunks from the order buffer.
	return w.writeResults(output, remaining) // Write these remaining chunks.
}

// writeResults iterates through a slice of TaskResults and writes each one to the output stream.
func (w *chunkWriter) writeResults(output io.Writer, results []TaskResult) error {
	for _, result := range results { // Iterate over each result in the provided slice.
		if err := w.writeResult(output, result); err != nil { // Write an individual result.
			return err // Propagate any error from writing a single result.
		}
	}
	return nil // Return nil if all results are written successfully.
}

// writeResult writes a single TaskResult's data to the output stream.
// For encryption, it prefixes the data with its size. It also updates the progress bar.
func (w *chunkWriter) writeResult(output io.Writer, result TaskResult) error {
	if w.processing == options.Encryption { // If encrypting, write the chunk size as a prefix.
		if err := w.writeChunkSize(output, len(result.Data)); err != nil {
			return fmt.Errorf("writing chunk size: %w", err) // Handle error during size writing.
		}
	}

	if _, err := output.Write(result.Data); err != nil { // Write the actual data chunk to the output.
		return fmt.Errorf("writing chunk data: %w", err) // Handle error during data writing.
	}

	if w.bar != nil { // If a progress bar is available, update it.
		if err := w.bar.Add(int64(result.Size)); err != nil {
			return fmt.Errorf("updating progress: %w", err) // Handle error during progress bar update.
		}
	}

	return nil // Return nil on successful writing of the result.
}

// writeChunkSize writes a 4-byte big-endian representation of the chunk size to the output stream.
// This is used during encryption to prefix each encrypted chunk with its length.
func (w *chunkWriter) writeChunkSize(output io.Writer, size int) error {
	if size < 0 || size > math.MaxUint32 { // Validate that the chunk size is within representable bounds.
		return fmt.Errorf("chunk size out of range: %d", size) // Return error for out-of-range size.
	}

	var buffer [config.ChunkHeaderSize]byte             // Create a 4-byte buffer for the size.
	binary.BigEndian.PutUint32(buffer[:], uint32(size)) // Convert integer size to 4-byte big-endian and put into buffer.
	if _, err := output.Write(buffer[:]); err != nil {  // Write the size buffer to the output stream.
		return fmt.Errorf("chunk size write failed: %w", err) // Handle error during writing.
	}

	return nil // Return nil on successful writing of the chunk size.
}
