package concurrent

import (
	"context"
	"sync"

	"github.com/hambosto/sweetbyte/internal/stream/processing"
	"github.com/hambosto/sweetbyte/internal/types"
)

type ConcurrentExecutor struct {
	dataProcessing *processing.DataProcessing
	concurrency    int
}

func NewConcurrentExecutor(dataProcessing *processing.DataProcessing, concurrency int) *ConcurrentExecutor {
	return &ConcurrentExecutor{
		dataProcessing: dataProcessing,
		concurrency:    concurrency,
	}
}

func (e *ConcurrentExecutor) Process(ctx context.Context, tasks <-chan types.Task, mode types.Processing) <-chan types.TaskResult {
	results := make(chan types.TaskResult, e.concurrency)

	go func() {
		defer close(results)

		var wg sync.WaitGroup
		for i := 0; i < e.concurrency; i++ {
			wg.Add(1)
			go e.worker(ctx, &wg, tasks, results)
		}
		wg.Wait()
	}()

	return results
}

func (e *ConcurrentExecutor) worker(ctx context.Context, wg *sync.WaitGroup, tasks <-chan types.Task, results chan<- types.TaskResult) {
	defer wg.Done()

	for {
		select {
		case <-ctx.Done():
			return
		case task, ok := <-tasks:
			if !ok {
				return
			}
			result := e.dataProcessing.Process(ctx, task)
			select {
			case results <- result:
			case <-ctx.Done():
				return
			}
		}
	}
}
