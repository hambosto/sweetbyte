package stream

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/types"
	"github.com/hambosto/sweetbyte/utils"
)

type ChunkReader struct {
	processing  types.Processing
	chunkSize   int
	concurrency int
}

func NewChunkReader(processing types.Processing, chunkSize, concurrency int) *ChunkReader {
	return &ChunkReader{
		processing:  processing,
		chunkSize:   chunkSize,
		concurrency: concurrency,
	}
}

func (r *ChunkReader) ReadChunks(ctx context.Context, input io.Reader) (<-chan types.Task, <-chan error) {
	taskChan := make(chan types.Task, r.concurrency)
	errChan := make(chan error, 1)

	go func() {
		defer close(taskChan)
		defer close(errChan)

		var err error

		switch r.processing {
		case types.Encryption:
			err = r.readForEncryption(ctx, input, taskChan)
		case types.Decryption:
			err = r.readForDecryption(ctx, input, taskChan)
		default:
			err = fmt.Errorf("unknown processing type: %d", r.processing)
		}

		if err != nil && !errors.Is(err, context.Canceled) {
			select {
			case errChan <- err:
			case <-ctx.Done():
			}
		}
	}()

	return taskChan, errChan
}

func (r *ChunkReader) readForEncryption(ctx context.Context, reader io.Reader, tasks chan<- types.Task) error {
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

		task := types.Task{
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

func (r *ChunkReader) readForDecryption(ctx context.Context, reader io.Reader, tasks chan<- types.Task) error {
	var index uint64

	for {

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		var sizeBuffer [4]byte
		_, err := io.ReadFull(reader, sizeBuffer[:])
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		chunkLen := utils.FromBytes[uint32](sizeBuffer[:])

		if chunkLen == 0 {
			continue
		}

		data := make([]byte, chunkLen)
		if _, err := io.ReadFull(reader, data); err != nil {
			return fmt.Errorf("failed to read chunk data (length: %d): %w", chunkLen, err)
		}

		task := types.Task{
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
