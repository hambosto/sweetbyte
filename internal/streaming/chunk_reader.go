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
)

// chunkReader implements the ChunkReader interface.
// It is responsible for reading data from an input stream in chunks,
// adapting its behavior based on whether the operation is encryption or decryption.
type chunkReader struct {
	processing options.Processing // The type of processing (encryption or decryption) to guide reading behavior.
	chunkSize  int                // The desired size of chunks for encryption.
}

// NewChunkReader creates and returns a new ChunkReader instance.
// It initializes the reader with the specified processing type and chunk size.
func NewChunkReader(processing options.Processing, chunkSize int) ChunkReader {
	return &chunkReader{
		processing: processing, // Set the processing type.
		chunkSize:  chunkSize,  // Set the chunk size.
	}
}

// ReadChunks reads data from the input stream and emits them as Tasks through a channel.
// It runs in a goroutine and handles errors, including context cancellation.
// The reading mechanism differs based on whether it's for encryption or decryption.
func (r *chunkReader) ReadChunks(ctx context.Context, input io.Reader) (<-chan Task, <-chan error) {
	taskChan := make(chan Task)    // Channel to send processed tasks.
	errChan := make(chan error, 1) // Buffered channel to send errors.

	go func() {
		defer close(taskChan) // Close task channel when the goroutine exits.
		defer close(errChan)  // Close error channel when the goroutine exits.

		var err error
		switch r.processing {
		case options.Encryption: // If the operation is encryption, read raw data in fixed chunks.
			err = r.readForEncryption(ctx, input, taskChan)
		case options.Decryption: // If the operation is decryption, read prefixed chunks.
			err = r.readForDecryption(ctx, input, taskChan)
		default:
			err = fmt.Errorf("unknown processing type: %d", r.processing) // Handle unknown processing types.
		}

		if err != nil && err != context.Canceled { // If an error occurred and it's not due to context cancellation.
			select {
			case errChan <- err: // Attempt to send the error to the error channel.
			case <-ctx.Done(): // If context is canceled before sending, exit.
			}
		}
	}()

	return taskChan, errChan // Return the channels for tasks and errors.
}

// readForEncryption reads raw data from the input stream in fixed-size chunks for encryption.
// It continuously reads until EOF or context cancellation, sending each chunk as a Task.
func (r *chunkReader) readForEncryption(ctx context.Context, reader io.Reader, tasks chan<- Task) error {
	buffer := make([]byte, r.chunkSize) // Create a buffer of the specified chunk size.

	var index uint64 // Initialize chunk index.
	for {
		select {
		case <-ctx.Done(): // Check for context cancellation.
			return ctx.Err()
		default:
			// Continue if context is not cancelled.
		}

		n, err := reader.Read(buffer) // Read data into the buffer.
		if err == io.EOF {            // If end of file is reached, stop reading.
			return nil
		}
		if err != nil { // Handle other read errors.
			return fmt.Errorf("failed to read input: %w", err)
		}

		task := Task{
			Data:  make([]byte, n), // Create a new slice with the exact data read.
			Index: index,           // Assign the current chunk index.
		}
		copy(task.Data, buffer[:n]) // Copy the read data into the task's data slice.

		select {
		case tasks <- task: // Send the task to the tasks channel.
			index++ // Increment index for the next chunk.
		case <-ctx.Done(): // Check for context cancellation while sending.
			return ctx.Err()
		}
	}
}

// readForDecryption reads length-prefixed chunks from the input stream for decryption.
// It reads a 4-byte length header, then the data, and sends each as a Task.
func (r *chunkReader) readForDecryption(ctx context.Context, reader io.Reader, tasks chan<- Task) error {
	var index uint64 // Initialize chunk index.

	for {
		select {
		case <-ctx.Done(): // Check for context cancellation.
			return ctx.Err()
		default:
			// Continue if context is not cancelled.
		}

		chunkLen, err := r.readChunkSize(reader) // Read the 4-byte length prefix of the next chunk.
		if err == io.EOF {                       // If end of file is reached, stop reading.
			return nil
		}
		if err != nil { // Handle errors during chunk size reading.
			return err
		}

		if chunkLen == 0 { // Skip empty chunks if any.
			continue
		}

		data, err := r.readChunkData(reader, chunkLen) // Read the actual chunk data based on the length.
		if err != nil {                                // Handle errors during chunk data reading.
			return err
		}

		task := Task{
			Data:  data,  // Assign the read data.
			Index: index, // Assign the current chunk index.
		}

		select {
		case tasks <- task: // Send the task to the tasks channel.
			index++ // Increment index for the next chunk.
		case <-ctx.Done(): // Check for context cancellation while sending.
			return ctx.Err()
		}
	}
}

// readChunkSize reads a 4-byte length prefix from the reader and converts it to a uint32.
// This size indicates the length of the upcoming data chunk in the encrypted file format.
func (r *chunkReader) readChunkSize(reader io.Reader) (uint32, error) {
	var sizeBuffer [config.ChunkHeaderSize]byte // Allocate a buffer to hold the 4-byte chunk size header.

	// Attempt to read exactly ChunkHeaderSize (4) bytes from the reader into the buffer.
	_, err := io.ReadFull(reader, sizeBuffer[:])
	if err != nil {
		// If reading fails (e.g., EOF or other error), return 0 and the error.
		return 0, err
	}

	// Convert the 4-byte buffer from big-endian to uint32 to get the chunk size.
	return binary.BigEndian.Uint32(sizeBuffer[:]), nil
}

// readChunkData reads a specified 'length' of bytes from the reader.
// It ensures that the entire chunk data is read.
func (r *chunkReader) readChunkData(reader io.Reader, length uint32) ([]byte, error) {
	if length > math.MaxInt32 { // Prevent allocation of excessively large chunks.
		return nil, fmt.Errorf("chunk size exceeds maximum allowed: %d (max: %d)", length, math.MaxInt32) // Return error for oversized chunks.
	}

	data := make([]byte, length)                         // Create a byte slice of the specified length.
	if _, err := io.ReadFull(reader, data); err != nil { // Read exactly 'length' bytes into the data slice.
		return nil, fmt.Errorf("failed to read chunk data (length: %d): %w", length, err) // Propagate error if read fails.
	}

	return data, nil // Return the read data chunk.
}
