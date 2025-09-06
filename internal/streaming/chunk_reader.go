// Package streaming provides functionalities for streaming data processing.
package streaming

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/options"
	"github.com/hambosto/sweetbyte/internal/utils"
)

// ChunkReader defines the interface for reading chunks from an input stream.
type ChunkReader interface {
	// ReadChunks reads chunks from the input stream and sends them to a channel.
	ReadChunks(ctx context.Context, input io.Reader) (<-chan Task, <-chan error)
}

// chunkReader implements the ChunkReader interface.
type chunkReader struct {
	processing  options.Processing
	chunkSize   int
	concurrency int
}

// NewChunkReader creates a new ChunkReader.
func NewChunkReader(processing options.Processing, chunkSize, concurrency int) ChunkReader {
	return &chunkReader{
		processing:  processing,
		chunkSize:   chunkSize,
		concurrency: concurrency,
	}
}

// ReadChunks reads chunks from the input stream and sends them to a channel.
func (r *chunkReader) ReadChunks(ctx context.Context, input io.Reader) (<-chan Task, <-chan error) {
	taskChan := make(chan Task, r.concurrency)
	errChan := make(chan error, 1)

	go func() {
		defer close(taskChan)
		defer close(errChan)

		var err error

		// Read chunks based on the processing type.
		switch r.processing {
		case options.Encryption:
			err = r.readForEncryption(ctx, input, taskChan)
		case options.Decryption:
			err = r.readForDecryption(ctx, input, taskChan)
		default:
			err = fmt.Errorf("unknown processing type: %d", r.processing)
		}

		// Send any error to the error channel.
		if err != nil && !errors.Is(err, context.Canceled) {
			select {
			case errChan <- err:
			case <-ctx.Done():
			}
		}
	}()

	return taskChan, errChan
}

// readForEncryption reads chunks for encryption.
func (r *chunkReader) readForEncryption(ctx context.Context, reader io.Reader, tasks chan<- Task) error {
	buffer := make([]byte, r.chunkSize)

	var index uint64
	for {
		// Check for cancellation.
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Read a chunk from the input stream.
		n, err := reader.Read(buffer)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("failed to read input: %w", err)
		}

		// Create a new task with the chunk data.
		task := Task{
			Data:  make([]byte, n),
			Index: index,
		}
		copy(task.Data, buffer[:n])

		// Send the task to the channel.
		select {
		case tasks <- task:
			index++
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// readForDecryption reads chunks for decryption.
func (r *chunkReader) readForDecryption(ctx context.Context, reader io.Reader, tasks chan<- Task) error {
	var index uint64

	for {
		// Check for cancellation.
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Read the chunk size.
		chunkLen, err := r.readChunkSize(reader)
		if err == io.EOF {
			return nil
		}

		if err != nil {
			return err
		}

		if chunkLen == 0 {
			continue
		}

		// Read the chunk data.
		data, err := r.readChunkData(reader, chunkLen)
		if err != nil {
			return err
		}

		// Create a new task with the chunk data.
		task := Task{
			Data:  data,
			Index: index,
		}

		// Send the task to the channel.
		select {
		case tasks <- task:
			index++
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// readChunkSize reads the size of a chunk from the reader.
func (r *chunkReader) readChunkSize(reader io.Reader) (uint32, error) {
	var sizeBuffer [4]byte
	_, err := io.ReadFull(reader, sizeBuffer[:])
	if err != nil {
		return 0, err
	}
	return utils.FromBytes[uint32](sizeBuffer[:]), nil
}

// readChunkData reads the data of a chunk from the reader.
func (r *chunkReader) readChunkData(reader io.Reader, length uint32) ([]byte, error) {
	data := make([]byte, length)
	if _, err := io.ReadFull(reader, data); err != nil {
		return nil, fmt.Errorf("failed to read chunk data (length: %d): %w", length, err)
	}

	return data, nil
}
