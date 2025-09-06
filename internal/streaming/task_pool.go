package streaming

import (
	"context"
	"fmt"

	"github.com/hambosto/sweetbyte/internal/options"
	"github.com/hambosto/sweetbyte/internal/processor"
)

type TaskProcessor interface {
	Process(ctx context.Context, task Task) TaskResult
}

type taskProcessor struct {
	processor  processor.Processor
	processing options.Processing
}

func NewTaskProcessor(key []byte, processing options.Processing) (TaskProcessor, error) {
	proc, err := processor.NewProcessor(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create processor: %w", err)
	}

	return &taskProcessor{
		processor:  proc,
		processing: processing,
	}, nil
}

func (tp *taskProcessor) Process(ctx context.Context, task Task) TaskResult {
	select {
	case <-ctx.Done():
		return TaskResult{
			Index: task.Index,
			Err:   ctx.Err(),
		}
	default:
	}

	var output []byte
	var err error

	switch tp.processing {
	case options.Encryption:
		output, err = tp.processor.Encrypt(task.Data)
	case options.Decryption:
		output, err = tp.processor.Decrypt(task.Data)
	default:
		err = fmt.Errorf("unknown processing type: %d", tp.processing)
	}

	size := tp.calculateProgressSize(task.Data, output)
	return TaskResult{
		Index: task.Index,
		Data:  output,
		Size:  size,
		Err:   err,
	}
}

func (tp *taskProcessor) calculateProgressSize(input, output []byte) int {
	if tp.processing == options.Encryption {
		return len(input)
	}
	return len(output)
}
