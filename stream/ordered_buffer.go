package stream

import (
	"slices"
	"sync"
)

type OrderedBuffer interface {
	Add(result TaskResult) []TaskResult
	Flush() []TaskResult
}

type orderedBuffer struct {
	mu      sync.Mutex
	results map[uint64]TaskResult
	next    uint64
}

func NewOrderedBuffer() OrderedBuffer {
	return &orderedBuffer{
		results: make(map[uint64]TaskResult),
		next:    0,
	}
}

func (b *orderedBuffer) Add(result TaskResult) []TaskResult {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.results[result.Index] = result
	var ready []TaskResult

	for {
		if result, exists := b.results[b.next]; exists {
			ready = append(ready, result)
			delete(b.results, b.next)
			b.next++
		} else {
			break
		}
	}

	return ready
}

func (b *orderedBuffer) Flush() []TaskResult {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.results) == 0 {
		return nil
	}

	indices := make([]uint64, 0, len(b.results))
	for idx := range b.results {
		indices = append(indices, idx)
	}

	slices.Sort(indices)
	results := make([]TaskResult, len(indices))
	for i, idx := range indices {
		results[i] = b.results[idx]
	}

	clear(b.results)
	return results
}
