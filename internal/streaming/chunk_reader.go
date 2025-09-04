// Package streaming provides the core functionality for streaming encryption and decryption.
package streaming

import (
	"context"
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/options"
	"github.com/hambosto/sweetbyte/internal/utils"
)

// ChunkReader reads data from an io.Reader and splits it into chunks for processing.
type ChunkReader interface {
	ReadChunks(ctx context.Context, input io.Reader) (<-chan Task, <-chan error)
}

// chunkReader reads data from an io.Reader and splits it into chunks for processing.
// The reading strategy depends on whether the operation is encryption or decryption.
type chunkReader struct {
	processing  options.Processing
	chunkSize   int
	concurrency int
}

// NewChunkReader creates a new ChunkReader with the specified processing mode and chunk size.
func NewChunkReader(processing options.Processing, chunkSize, concurrency int) ChunkReader {
	return &chunkReader{
		processing:  processing,
		chunkSize:   chunkSize,
		concurrency: concurrency,
	}
}

// ReadChunks reads data from the input reader and sends it as tasks to a channel.
// It runs in a separate goroutine and returns a channel for tasks and a channel for errors.
func (r *chunkReader) ReadChunks(ctx context.Context, input io.Reader) (<-chan Task, <-chan error) {
	taskChan := make(chan Task, r.concurrency)
	errChan := make(chan error, 1)

	go func() {
		defer close(taskChan)
		defer close(errChan)

		var err error
		// Determine the reading strategy based on the processing mode.
		switch r.processing {
		case options.Encryption:
			err = r.readForEncryption(ctx, input, taskChan)
		case options.Decryption:
			err = r.readForDecryption(ctx, input, taskChan)
		default:
			err = fmt.Errorf("unknown processing type: %d", r.processing)
		}

		// If an error occurs (and it's not a context cancellation), send it to the error channel.
		if err != nil && err != context.Canceled {
			select {
			case errChan <- err:
			case <-ctx.Done():
			}
		}
	}()

	return taskChan, errChan
}

// readForEncryption reads the input stream into fixed-size chunks for encryption.
func (r *chunkReader) readForEncryption(ctx context.Context, reader io.Reader, tasks chan<- Task) error {
	buffer := make([]byte, r.chunkSize)

	var index uint64
	for {
		// Check for context cancellation before each read.
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:

		}

		// Read data into the buffer.
		n, err := reader.Read(buffer)
		if err == io.EOF {
			return nil // End of file reached.
		}
		if err != nil {
			return fmt.Errorf("failed to read input: %w", err)
		}

		// Create a task with the read data.
		task := Task{
			Data:  make([]byte, n),
			Index: index,
		}
		copy(task.Data, buffer[:n])

		// Send the task to the channel, or exit if the context is canceled.
		select {
		case tasks <- task:
			index++
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// readForDecryption reads the input stream, which is expected to have a chunk size header before each chunk.
func (r *chunkReader) readForDecryption(ctx context.Context, reader io.Reader, tasks chan<- Task) error {
	var index uint64

	for {
		// Check for context cancellation.
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Read the size of the next chunk.
		chunkLen, err := r.readChunkSize(reader)
		if err == io.EOF {
			return nil // End of file.
		}

		if err != nil {
			return err
		}

		// If chunk length is zero, skip to the next one.
		if chunkLen == 0 {
			continue
		}

		// Read the chunk data based on the read size.
		data, err := r.readChunkData(reader, chunkLen)
		if err != nil {
			return err
		}

		// Create and send the task.
		task := Task{
			Data:  data,
			Index: index,
		}

		select {
		case tasks <- task:
			index++
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// readChunkSize reads the 4-byte chunk size header from the reader.
func (r *chunkReader) readChunkSize(reader io.Reader) (uint32, error) {
	var sizeBuffer [4]byte
	_, err := io.ReadFull(reader, sizeBuffer[:])
	if err != nil {
		return 0, err
	}
	return utils.FromBytes[uint32](sizeBuffer[:]), nil
}

// readChunkData reads a chunk of a given length from the reader.
func (r *chunkReader) readChunkData(reader io.Reader, length uint32) ([]byte, error) {
	data := make([]byte, length)
	if _, err := io.ReadFull(reader, data); err != nil {
		return nil, fmt.Errorf("failed to read chunk data (length: %d): %w", length, err)
	}

	return data, nil
}
