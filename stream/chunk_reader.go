package stream

import (
	"context"
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/types"
	"github.com/hambosto/sweetbyte/utils"
)

// ChunkReader handles reading input data and splitting it into chunks for processing.
// It supports both encryption and decryption modes with configurable chunk size and concurrency.
type ChunkReader struct {
	processing  types.Processing // The type of processing (encryption/decryption) to perform
	chunkSize   int              // Size of each data chunk to read
	concurrency int              // Number of concurrent operations allowed
}

// NewChunkReader creates and returns a new ChunkReader instance with the specified
// processing type, chunk size, and concurrency level.
func NewChunkReader(processing types.Processing, chunkSize, concurrency int) *ChunkReader {
	return &ChunkReader{
		processing:  processing,
		chunkSize:   chunkSize,
		concurrency: concurrency,
	}
}

// ReadChunks reads data from the input reader and sends tasks to be processed.
// It returns two channels: one for tasks and one for errors.
// The method handles both encryption and decryption modes based on the ChunkReader's configuration.
func (r *ChunkReader) ReadChunks(ctx context.Context, input io.Reader) (<-chan types.Task, <-chan error) {
	tasks := make(chan types.Task, r.concurrency) // Buffered channel to hold tasks
	errCh := make(chan error, 1)                  // Buffered channel to hold errors

	go func() {
		defer close(tasks)
		defer close(errCh)

		var err error
		// Process data based on the configured processing type
		switch r.processing {
		case types.Encryption:
			// For encryption, read raw data chunks
			err = r.readForEncryption(ctx, input, tasks)
		case types.Decryption:
			// For decryption, read structured chunks with size headers
			err = r.readForDecryption(ctx, input, tasks)
		default:
			err = fmt.Errorf("unknown processing type: %d", r.processing)
		}

		// Send error to error channel if context is not cancelled
		if err != nil && ctx.Err() == nil {
			select {
			case errCh <- err:
			case <-ctx.Done():
			}
		}
	}()

	return tasks, errCh
}

// readForEncryption reads data for encryption mode by splitting the input into
// fixed-size chunks and sending them as tasks to be processed.
func (r *ChunkReader) readForEncryption(ctx context.Context, reader io.Reader, tasks chan<- types.Task) error {
	buffer := make([]byte, r.chunkSize) // Buffer to read data chunks
	var index uint64                    // Index for tracking chunk order

	for {
		// Check if context has been cancelled
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Read data into buffer
		n, err := reader.Read(buffer)
		if n > 0 {
			// Create a task with the read data
			task := types.Task{
				Data:  make([]byte, n), // Copy only the actual read bytes
				Index: index,
			}
			copy(task.Data, buffer[:n]) // Copy data to avoid buffer reference

			// Send task to processing channel
			select {
			case tasks <- task:
				index++ // Increment index for next chunk
			case <-ctx.Done():
				return ctx.Err()
			}
		}

		// Handle end of file or error
		if err == io.EOF {
			return nil // EOF is normal end condition
		}
		if err != nil {
			return fmt.Errorf("failed to read input: %w", err)
		}
	}
}

// readForDecryption reads data for decryption mode by reading chunk size headers
// followed by the actual chunk data, then sending chunks as tasks to be processed.
func (r *ChunkReader) readForDecryption(ctx context.Context, reader io.Reader, tasks chan<- types.Task) error {
	var index uint64 // Index for tracking chunk order

	for {
		// Check if context has been cancelled
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Read the 4-byte size header for the next chunk
		var sizeBuffer [4]byte
		_, err := io.ReadFull(reader, sizeBuffer[:])
		if err == io.EOF {
			return nil // EOF is normal end condition
		}
		if err != nil {
			return fmt.Errorf("failed to read chunk size: %w", err)
		}

		// Convert the size header bytes to uint32
		chunkLen := utils.FromBytes[uint32](sizeBuffer[:])
		if chunkLen == 0 {
			continue // Skip zero-length chunks
		}

		// Read the actual chunk data based on the size header
		data := make([]byte, chunkLen)
		if _, err := io.ReadFull(reader, data); err != nil {
			return fmt.Errorf("failed to read chunk data (length: %d): %w", chunkLen, err)
		}

		// Create and send task
		task := types.Task{
			Data:  data,  // The actual chunk data
			Index: index, // Current index for ordering
		}

		// Send task to processing channel
		select {
		case tasks <- task:
			index++ // Increment index for next chunk
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}
