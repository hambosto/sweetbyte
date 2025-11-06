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
		case result, ok := <-results:
			if !ok {
				return w.flushRemaining(output)
			}

			if result.Err != nil {
				return fmt.Errorf("processing chunk %d: %w", result.Index, result.Err)
			}

			ready := w.buffer.Add(result)
			if err := w.writeResults(output, ready); err != nil {
				return err
			}
		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (w *ChunkWriter) flushRemaining(output io.Writer) error {
	remaining := w.buffer.Flush()
	return w.writeResults(output, remaining)
}

func (w *ChunkWriter) writeResults(output io.Writer, results []types.TaskResult) error {
	for _, result := range results {
		if err := w.writeResult(output, result); err != nil {
			return err
		}
	}
	return nil
}

func (w *ChunkWriter) writeResult(output io.Writer, result types.TaskResult) error {
	if w.processing == types.Encryption {
		if err := w.writeChunkSize(output, len(result.Data)); err != nil {
			return fmt.Errorf("writing chunk size: %w", err)
		}
	}

	if _, err := output.Write(result.Data); err != nil {
		return fmt.Errorf("writing chunk data: %w", err)
	}

	if err := w.bar.Add(int64(result.Size)); err != nil {
		return fmt.Errorf("updating progress: %w", err)
	}

	return nil
}

func (w *ChunkWriter) writeChunkSize(output io.Writer, size int) error {
	if size < 0 || size > int(^uint32(0)) {
		return fmt.Errorf("size %d exceeds maximum allowed size for uint32", size)
	}
	
	buffer := utils.ToBytes(uint32(size))
	if _, err := output.Write(buffer); err != nil {
		return fmt.Errorf("chunk size write failed: %w", err)
	}

	return nil
}
