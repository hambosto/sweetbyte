// Package streaming provides the core functionality for streaming encryption and decryption.
package streaming

import (
	"context"
	"sync"
)

// WorkerPool manages a pool of workers for processing tasks concurrently.
type WorkerPool interface {
	Process(ctx context.Context, tasks <-chan Task) <-chan TaskResult
}

// defaultWorkerPool manages a pool of workers for processing tasks concurrently.
type defaultWorkerPool struct {
	processor   TaskProcessor
	concurrency int
}

// NewWorkerPool creates a new workerPool with the given task processor and concurrency level.
func NewWorkerPool(processor TaskProcessor, concurrency int) WorkerPool {
	return &defaultWorkerPool{
		processor:   processor,
		concurrency: concurrency,
	}
}

// Process starts the worker pool and processes tasks from the input channel.
// It returns a channel of task results.
func (p *defaultWorkerPool) Process(ctx context.Context, tasks <-chan Task) <-chan TaskResult {
	// Create a buffered channel for results.
	results := make(chan TaskResult, p.concurrency)
	go func() {
		// Close the results channel when all workers are done.
		defer close(results)
		var wg sync.WaitGroup
		// Start the workers.
		for i := 0; i < p.concurrency; i++ {
			wg.Add(1)
			go p.worker(ctx, &wg, tasks, results)
		}

		// Wait for all workers to finish.
		wg.Wait()
	}()
	return results
}

// worker is a single worker that processes tasks from the tasks channel and sends results to the results channel.
func (p *defaultWorkerPool) worker(ctx context.Context, wg *sync.WaitGroup, tasks <-chan Task, results chan<- TaskResult) {
	defer wg.Done()
	for {
		select {
		// Read a task from the tasks channel.
		case task, ok := <-tasks:
			// If the channel is closed, return.
			if !ok {
				return
			}
			// Process the task.
			result := p.processor.Process(ctx, task)
			// Send the result to the results channel.
			select {
			case results <- result:
			// If the context is canceled, return.
			case <-ctx.Done():
				return
			}
		// If the context is canceled, return.
		case <-ctx.Done():
			return
		}
	}
}