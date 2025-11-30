package stream

import (
	"context"
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/types"
	"github.com/hambosto/sweetbyte/internal/ui"
	"github.com/hambosto/sweetbyte/internal/utils"
)

type ChunkWriter struct {
	mode          types.Processing
	progressBar   *ui.ProgressBar
	orderedBuffer *OrderedBuffer
}

func NewChunkWriter(mode types.Processing, progressBar *ui.ProgressBar) *ChunkWriter {
	return &ChunkWriter{
		mode:          mode,
		progressBar:   progressBar,
		orderedBuffer: NewOrderedBuffer(),
	}
}

func (w *ChunkWriter) Write(ctx context.Context, output io.Writer, results <-chan types.TaskResult) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case result, ok := <-results:
			if !ok {
				return w.writeOrdered(output, w.orderedBuffer.Flush())
			}

			if result.Err != nil {
				return fmt.Errorf("task %d failed: %w", result.Index, result.Err)
			}

			ready := w.orderedBuffer.Add(result)
			if err := w.writeOrdered(output, ready); err != nil {
				return err
			}
		}
	}
}

func (w *ChunkWriter) writeOrdered(output io.Writer, results []types.TaskResult) error {
	for _, res := range results {
		switch w.mode {
		case types.Encryption:
			sizePrefix := utils.ToBytes[uint32](len(res.Data))
			if _, err := output.Write(sizePrefix); err != nil {
				return fmt.Errorf("writing chunk size prefix: %w", err)
			}
			if _, err := output.Write(res.Data); err != nil {
				return fmt.Errorf("writing chunk data: %w", err)
			}
		case types.Decryption:
			if _, err := output.Write(res.Data); err != nil {
				return fmt.Errorf("writing chunk data: %w", err)
			}
		default:
			return fmt.Errorf("unsupported processing mode: %v", w.mode)
		}

		if err := w.progressBar.Add(int64(res.Size)); err != nil {
			return fmt.Errorf("updating progress: %w", err)
		}
	}
	return nil
}
