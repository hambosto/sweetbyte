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

// chunkReader converts an input stream into chunked `Task`s for the
// concurrent processing pipeline.
//
// Behavior by mode:
//   - Encryption: reads fixed-size plaintext chunks directly from `io.Reader`.
//   - Decryption: reads a 4-byte big-endian length prefix, then the chunk.
//
// The length-prefixed format is only used for the encrypted stream so that the
// writer can preserve chunk boundaries and the reader can detect truncation.
type chunkReader struct {
	processing options.Processing
	chunkSize  int
}

// NewChunkReader creates a new chunk reader
func NewChunkReader(processing options.Processing, chunkSize int) ChunkReader {
	return &chunkReader{
		processing: processing,
		chunkSize:  chunkSize,
	}
}

// ReadChunks reads data from `input` and emits `Task`s to a channel.
// The error channel will receive a single error (if any) and then close.
// Context cancellation is honored and propagated to callers.
func (r *chunkReader) ReadChunks(ctx context.Context, input io.Reader) (<-chan Task, <-chan error) {
	taskChan := make(chan Task)
	errChan := make(chan error, 1)

	go func() {
		defer close(taskChan)
		defer close(errChan)

		var err error
		switch r.processing {
		case options.Encryption:
			err = r.readForEncryption(ctx, input, taskChan)
		case options.Decryption:
			err = r.readForDecryption(ctx, input, taskChan)
		default:
			err = fmt.Errorf("unknown processing type: %d", r.processing)
		}

		if err != nil && err != context.Canceled {
			select {
			case errChan <- err:
			case <-ctx.Done():
			}
		}
	}()

	return taskChan, errChan
}

// readForEncryption reads raw plaintext in fixed-size chunks of `r.chunkSize`.
// It stops on EOF and returns any other read error.
func (r *chunkReader) readForEncryption(ctx context.Context, reader io.Reader, tasks chan<- Task) error {
	buffer := make([]byte, r.chunkSize)
	var index uint64

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		n, err := reader.Read(buffer)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("failed to read input: %w", err)
		}

		task := Task{
			Data:  make([]byte, n),
			Index: index,
		}
		copy(task.Data, buffer[:n])

		select {
		case tasks <- task:
			index++
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

// readForDecryption reads a sequence of length-prefixed chunks.
// Each chunk begins with a 4-byte big-endian size header followed by the data.
// Empty chunks (size==0) are ignored.
func (r *chunkReader) readForDecryption(ctx context.Context, reader io.Reader, tasks chan<- Task) error {
	var index uint64

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		chunkLen, err := r.readChunkSize(reader)
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}

		if chunkLen == 0 {
			continue // Skip empty chunks
		}

		data, err := r.readChunkData(reader, chunkLen)
		if err != nil {
			return err
		}

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

// readChunkSize reads the 4-byte big-endian chunk size header.
// Returns io.EOF if there is no more data to read.
func (r *chunkReader) readChunkSize(reader io.Reader) (uint32, error) {
	var sizeBuffer [config.ChunkHeaderSize]byte
	_, err := io.ReadFull(reader, sizeBuffer[:])
	if err != nil {
		return 0, fmt.Errorf("failed to read chunk size: %w", err)
	}
	return binary.BigEndian.Uint32(sizeBuffer[:]), nil
}

// readChunkData reads exactly `length` bytes of chunk data.
// Guards against excessively large sizes to avoid integer overflow.
func (r *chunkReader) readChunkData(reader io.Reader, length uint32) ([]byte, error) {
	if length > math.MaxInt32 {
		return nil, fmt.Errorf("chunk size exceeds maximum allowed: %d (max: %d)", length, math.MaxInt32)
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(reader, data); err != nil {
		return nil, fmt.Errorf("failed to read chunk data: %w", err)
	}
	return data, nil
}
