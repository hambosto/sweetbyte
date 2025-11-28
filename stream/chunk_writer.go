package stream

import (
	"context"
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/types"
	"github.com/hambosto/sweetbyte/ui"
	"github.com/hambosto/sweetbyte/utils"
)

type ChunkWriter struct {
	processing types.Processing
	buffer     *OrderedBuffer
	bar        *ui.ProgressBar
}

func NewChunkWriter(processing types.Processing, bar *ui.ProgressBar) *ChunkWriter {
	return &ChunkWriter{
		processing: processing,
		buffer:     NewOrderedBuffer(),
		bar:        bar,
	}
}

func (w *ChunkWriter) WriteChunks(ctx context.Context, output io.Writer, results <-chan types.TaskResult) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case result, ok := <-results:
			if !ok {
				return w.writeResults(output, w.buffer.Flush())
			}
			if result.Err != nil {
				return fmt.Errorf("processing chunk %d: %w", result.Index, result.Err)
			}
			if err := w.writeResults(output, w.buffer.Add(result)); err != nil {
				return err
			}
		}
	}
}

func (w *ChunkWriter) writeResults(output io.Writer, results []types.TaskResult) error {
	for _, res := range results {
		if w.processing == types.Encryption {
			size := len(res.Data)
			buffer := utils.ToBytes(uint32(size))
			if _, err := output.Write(buffer); err != nil {
				return fmt.Errorf("writing chunk size: %w", err)
			}
		}
		if _, err := output.Write(res.Data); err != nil {
			return fmt.Errorf("writing chunk data: %w", err)
		}
		if err := w.bar.Add(int64(res.Size)); err != nil {
			return fmt.Errorf("updating progress: %w", err)
		}
	}
	return nil
}
