package stream

import (
	"context"
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/types"
	"github.com/hambosto/sweetbyte/internal/utils"
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
	tasks := make(chan types.Task, r.concurrency)
	errCh := make(chan error, 1)

	go func() {
		defer close(tasks)
		defer close(errCh)

		var err error
		switch r.processing {
		case types.Encryption:
			err = r.readForEncryption(ctx, input, tasks)
		case types.Decryption:
			err = r.readForDecryption(ctx, input, tasks)
		default:
			err = fmt.Errorf("unknown processing type: %d", r.processing)
		}

		if err != nil && ctx.Err() == nil {
			select {
			case errCh <- err:
			case <-ctx.Done():
			}
		}
	}()

	return tasks, errCh
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
		if n > 0 {
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

		if err == io.EOF {
			return nil
		}
		if err != nil {
			return fmt.Errorf("failed to read input: %w", err)
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
			return fmt.Errorf("failed to read chunk size: %w", err)
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
