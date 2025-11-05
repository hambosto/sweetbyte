package stream

import (
	"context"
	"sync"

	"sweetbyte/types"
)

type WorkerPool struct {
	processor   *TaskProcessor
	concurrency int
}

func NewWorkerPool(processor *TaskProcessor, concurrency int) *WorkerPool {
	return &WorkerPool{
		processor:   processor,
		concurrency: concurrency,
	}
}

func (p *WorkerPool) Process(ctx context.Context, tasks <-chan types.Task) <-chan types.TaskResult {
	results := make(chan types.TaskResult, p.concurrency)
	go func() {
		defer close(results)
		var wg sync.WaitGroup

		for i := 0; i < p.concurrency; i++ {
			wg.Add(1)
			go p.worker(ctx, &wg, tasks, results)
		}
		wg.Wait()
	}()
	return results
}

func (p *WorkerPool) worker(ctx context.Context, wg *sync.WaitGroup, tasks <-chan types.Task, results chan<- types.TaskResult) {
	defer wg.Done()
	for {
		select {
		case task, ok := <-tasks:
			if !ok {
				return
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
