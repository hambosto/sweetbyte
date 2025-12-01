package chunk

import (
	"context"
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/stream/buffer"
	"github.com/hambosto/sweetbyte/internal/types"
	"github.com/hambosto/sweetbyte/internal/ui/bar"
	"github.com/hambosto/sweetbyte/internal/utils"
)

type ChunkWriter struct {
	mode             types.Processing
	progressBar      *bar.ProgressBar
	sequentialBuffer *buffer.SequentialBuffer
}

func NewChunkWriter(mode types.Processing, progressBar *bar.ProgressBar) (*ChunkWriter, error) {
	seqBuf, err := buffer.NewSequentialBuffer(0)
	if err != nil {
		return nil, fmt.Errorf("creating sequential buffer: %w", err)
	}
	return &ChunkWriter{
		mode:             mode,
		progressBar:      progressBar,
		sequentialBuffer: seqBuf,
	}, nil
}

func (w *ChunkWriter) Write(ctx context.Context, output io.Writer, results <-chan types.TaskResult) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case result, ok := <-results:
			if !ok {
				return w.writeOrdered(output, w.sequentialBuffer.Flush())
			}

			if result.Err != nil {
				return fmt.Errorf("task %d failed: %w", result.Index, result.Err)
			}

			ready := w.sequentialBuffer.Add(result)
			if err := w.writeOrdered(output, ready); err != nil {
				return err
			}
		}
	}
}

func (w *ChunkWriter) writeOrdered(output io.Writer, results []types.TaskResult) error {
	switch w.mode {
	case types.Encryption:
		for _, res := range results {
			sizePrefix := utils.ToBytes[uint32](len(res.Data))
			if _, err := output.Write(sizePrefix); err != nil {
				return fmt.Errorf("writing chunk size prefix: %w", err)
			}
			if _, err := output.Write(res.Data); err != nil {
				return fmt.Errorf("writing chunk data: %w", err)
			}
			if err := w.progressBar.Add(int64(res.Size)); err != nil {
				return fmt.Errorf("updating progress: %w", err)
			}
		}
	case types.Decryption:
		for _, res := range results {
			if _, err := output.Write(res.Data); err != nil {
				return fmt.Errorf("writing chunk data: %w", err)
			}
			if err := w.progressBar.Add(int64(res.Size)); err != nil {
				return fmt.Errorf("updating progress: %w", err)
			}
		}
	default:
		return fmt.Errorf("unsupported processing mode: %v", w.mode)
	}

	return nil
}
