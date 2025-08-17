// Package streaming defines the interfaces and core components for efficient, chunk-based file processing.
// It provides a flexible architecture for handling large files through concurrent operations.
package streaming

import (
	"context"
	"sync"
)

// workerPool manages a pool of goroutines (workers) to concurrently process tasks.
// It distributes incoming tasks to available workers and collects their results.
type workerPool struct {
	processor   TaskProcessor // The TaskProcessor instance that each worker will use to process tasks.
	concurrency int           // The number of worker goroutines to run concurrently.
}

// NewWorkerPool creates and returns a new workerPool instance.
// It initializes the pool with the given task processor and desired level of concurrency.
func NewWorkerPool(processor TaskProcessor, concurrency int) *workerPool {
	return &workerPool{
		processor:   processor,   // Assign the task processor.
		concurrency: concurrency, // Set the number of concurrent workers.
	}
}

// Process starts the worker pool to consume tasks from the `tasks` channel
// and return results through the `TaskResult` channel.
// It creates a fixed number of worker goroutines and waits for them to complete.
func (p *workerPool) Process(ctx context.Context, tasks <-chan Task) <-chan TaskResult {
	results := make(chan TaskResult, p.concurrency) // Create a buffered channel for results.
	go func() {
		defer close(results)                 // Ensure the results channel is closed when all tasks are processed.
		var wg sync.WaitGroup                // WaitGroup to synchronize worker goroutines.
		for i := 0; i < p.concurrency; i++ { // Start `concurrency` number of worker goroutines.
			wg.Add(1)                             // Increment the WaitGroup counter for each new worker.
			go p.worker(ctx, &wg, tasks, results) // Start a worker goroutine.
		}

		wg.Wait() // Wait for all worker goroutines to finish.
	}()
	return results // Return the channel where results will be sent.
}

// worker is a goroutine function that continuously fetches tasks from the `tasks` channel,
// processes them using the `TaskProcessor`, and sends the results to the `results` channel.
// It stops when the `tasks` channel is closed or the context is cancelled.
func (p *workerPool) worker(ctx context.Context, wg *sync.WaitGroup, tasks <-chan Task, results chan<- TaskResult) {
	defer wg.Done() // Decrement the WaitGroup counter when the worker exits.
	for {           // Loop indefinitely to process tasks.
		select {
		case task, ok := <-tasks: // Try to receive a task from the tasks channel.
			if !ok { // If the tasks channel is closed, this worker has no more tasks to process.
				return // Exit the worker goroutine.
			}
			result := p.processor.Process(ctx, task) // Process the received task.
			select {
			case results <- result: // Send the processing result to the results channel.
			case <-ctx.Done(): // If the context is cancelled while trying to send results.
				return // Exit the worker goroutine.
			}
		case <-ctx.Done(): // If the context is cancelled (e.g., pipeline error or shutdown).
			return // Exit the worker goroutine.
		}
	}
}
