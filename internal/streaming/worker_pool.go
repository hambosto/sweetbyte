package streaming

import (
	"context"
	"sync"

	"github.com/hambosto/sweetbyte/internal/types"
)

// workerPool manages concurrent task processing
type workerPool struct {
	processor   TaskProcessor
	concurrency int
}

// NewWorkerPool creates a new worker pool
func NewWorkerPool(processor TaskProcessor, concurrency int) *workerPool {
	return &workerPool{
		processor:   processor,
		concurrency: concurrency,
	}
}

// Process starts workers to process tasks concurrently
func (p *workerPool) Process(ctx context.Context, tasks <-chan types.Task) <-chan types.TaskResult {
	results := make(chan types.TaskResult)

	go func() {
		defer close(results)

		var wg sync.WaitGroup

		// Start workers
		for i := 0; i < p.concurrency; i++ {
			wg.Add(1)
			go p.worker(ctx, &wg, tasks, results)
		}

		// Wait for all workers to complete
		wg.Wait()
	}()

	return results
}

// worker processes tasks from the input channel
func (p *workerPool) worker(ctx context.Context, wg *sync.WaitGroup, tasks <-chan types.Task, results chan<- types.TaskResult) {
	defer wg.Done()

	for {
		select {
		case task, ok := <-tasks:
			if !ok {
				return // Channel closed
			}

			result := p.processor.Process(ctx, task)

			select {
			case results <- result:
			case <-ctx.Done():
				return
			}

		case <-ctx.Done():
			return
		}
	}
}
