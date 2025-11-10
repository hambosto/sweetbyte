package stream

import (
	"context"
	"fmt"
	"io"

	"sweetbyte/tui"
	"sweetbyte/types"
	"sweetbyte/utils"
)

type ChunkWriter struct {
	processing types.Processing
	buffer     *OrderedBuffer
	bar        *tui.ProgressBar
}

func NewChunkWriter(processing types.Processing, bar *tui.ProgressBar) *ChunkWriter {
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
	proc := w.processing == types.Encryption
	for _, res := range results {
		if proc {
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
