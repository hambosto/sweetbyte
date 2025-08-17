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

type chunkReader struct {
	processing options.Processing
	chunkSize  int
}

func NewChunkReader(processing options.Processing, chunkSize int) ChunkReader {
	return &chunkReader{
		processing: processing,
		chunkSize:  chunkSize,
	}
}

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
			continue
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

func (r *chunkReader) readChunkSize(reader io.Reader) (uint32, error) {
	var sizeBuffer [config.ChunkHeaderSize]byte

	_, err := io.ReadFull(reader, sizeBuffer[:])
	if err != nil {
		return 0, fmt.Errorf("failed to read chunk size: %w", err)
	}

	return binary.BigEndian.Uint32(sizeBuffer[:]), nil
}

func (r *chunkReader) readChunkData(reader io.Reader, length uint32) ([]byte, error) {
	if length > math.MaxInt32 {
		return nil, fmt.Errorf("chunk size exceeds maximum allowed: %d (max: %d)", length, math.MaxInt32)
	}

	data := make([]byte, length)
	if _, err := io.ReadFull(reader, data); err != nil {
		return nil, fmt.Errorf("failed to read chunk data (length: %d): %w", length, err)
	}

	return data, nil
}
