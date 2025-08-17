package streaming

import (
	"slices"
	"sync"
)

type orderBuffer struct {
	mu      sync.Mutex
	results map[uint64]TaskResult
	next    uint64
}

func NewOrderBuffer() OrderBuffer {
	return &orderBuffer{
		results: make(map[uint64]TaskResult),
		next:    0,
	}
}

func (b *orderBuffer) Add(result TaskResult) []TaskResult {
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

func (b *orderBuffer) Flush() []TaskResult {
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
