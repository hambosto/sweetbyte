// Package streaming provides functionalities for streaming data processing.
package streaming

import (
	"context"
	"sync"
)

// WorkerPool defines the interface for a worker pool that processes tasks concurrently.
type WorkerPool interface {
	// Process processes tasks from a channel and returns the results to a channel.
	Process(ctx context.Context, tasks <-chan Task) <-chan TaskResult
}

// workerPool implements the WorkerPool interface.
type workerPool struct {
	processor   TaskProcessor
	concurrency int
}

// NewWorkerPool creates a new WorkerPool.
func NewWorkerPool(processor TaskProcessor, concurrency int) WorkerPool {
	return &workerPool{
		processor:   processor,
		concurrency: concurrency,
	}
}

// Process processes tasks from a channel and returns the results to a channel.
func (p *workerPool) Process(ctx context.Context, tasks <-chan Task) <-chan TaskResult {
	results := make(chan TaskResult, p.concurrency)
	go func() {
		defer close(results)
		var wg sync.WaitGroup

		// Start the workers.
		for i := 0; i < p.concurrency; i++ {
			wg.Add(1)
			go p.worker(ctx, &wg, tasks, results)
		}

		wg.Wait()
	}()
	return results
}

// worker is a worker goroutine that processes tasks.
func (p *workerPool) worker(ctx context.Context, wg *sync.WaitGroup, tasks <-chan Task, results chan<- TaskResult) {
	defer wg.Done()
	for {
		select {
		// Read a task from the channel.
		case task, ok := <-tasks:
			// If the channel is closed, return.
			if !ok {
				return
			}

			// Process the task and send the result to the results channel.
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
