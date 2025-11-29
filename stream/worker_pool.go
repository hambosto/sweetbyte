package stream

import (
	"context"
	"sync"

	"github.com/hambosto/sweetbyte/types"
)

// WorkerPool manages a pool of worker goroutines that process tasks concurrently.
// It distributes incoming tasks among available workers and collects results.
type WorkerPool struct {
	processor   *TaskProcessor // The processor for handling individual tasks
	concurrency int            // Number of concurrent worker goroutines
}

// NewWorkerPool creates and returns a new WorkerPool instance with the specified
// processor and concurrency level.
func NewWorkerPool(processor *TaskProcessor, concurrency int) *WorkerPool {
	return &WorkerPool{
		processor:   processor,   // Set the task processor
		concurrency: concurrency, // Set the number of concurrent workers
	}
}

// Process starts the worker pool and processes incoming tasks concurrently.
// It returns a channel that receives processed task results as they complete.
func (p *WorkerPool) Process(ctx context.Context, tasks <-chan types.Task) <-chan types.TaskResult {
	// Create a buffered channel for results with capacity equal to concurrency
	results := make(chan types.TaskResult, p.concurrency)

	// Start the processing goroutine to manage workers
	go func() {
		defer close(results) // Close results channel when all workers finish

		var wg sync.WaitGroup // WaitGroup to track worker completion
		// Launch the specified number of worker goroutines
		for i := 0; i < p.concurrency; i++ {
			wg.Add(1) // Add worker to wait group
			// Start a worker goroutine
			go p.worker(ctx, &wg, tasks, results)
		}

		// Wait for all workers to complete before closing the results channel
		wg.Wait()
	}()

	return results
}

// worker processes tasks from the input channel until it's closed or context is cancelled.
// Each worker runs in its own goroutine and sends results to the results channel.
func (p *WorkerPool) worker(ctx context.Context, wg *sync.WaitGroup, tasks <-chan types.Task, results chan<- types.TaskResult) {
	defer wg.Done() // Mark this worker as done when the function returns

	for {
		// Check if context has been cancelled before attempting to read a task
		select {
		case <-ctx.Done():
			return // Exit if context is cancelled
		case task, ok := <-tasks:
			if !ok {
				return // Exit if tasks channel is closed (no more tasks)
			}

			// Process the task using the configured processor
			result := p.processor.Process(ctx, task)

			// Send the result to the results channel
			select {
			case results <- result:
				// Successfully sent result, continue to next task
			case <-ctx.Done():
				return // Exit if context is cancelled while trying to send result
			}
		}
	}
}
