package streaming

import (
	"context"
	"sync"
)

type WorkerPool interface {
	Process(ctx context.Context, tasks <-chan Task) <-chan TaskResult
}

type workerPool struct {
	processor   TaskProcessor
	concurrency int
}

func NewWorkerPool(processor TaskProcessor, concurrency int) WorkerPool {
	return &workerPool{
		processor:   processor,
		concurrency: concurrency,
	}
}

func (p *workerPool) Process(ctx context.Context, tasks <-chan Task) <-chan TaskResult {
	results := make(chan TaskResult, p.concurrency)
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

func (p *workerPool) worker(ctx context.Context, wg *sync.WaitGroup, tasks <-chan Task, results chan<- TaskResult) {
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
