package stream

import (
	"slices"
	"sync"

	"github.com/hambosto/sweetbyte/internal/types"
)

type OrderedBuffer struct {
	mu      sync.Mutex
	results map[uint64]types.TaskResult
	next    uint64
}

func NewOrderedBuffer() *OrderedBuffer {
	return &OrderedBuffer{
		results: make(map[uint64]types.TaskResult),
		next:    0,
	}
}

func (b *OrderedBuffer) Add(result types.TaskResult) []types.TaskResult {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.results[result.Index] = result
	var ready []types.TaskResult
	for {
		result, exists := b.results[b.next]
		if !exists {
			break
		}

		ready = append(ready, result)
		delete(b.results, b.next)
		b.next++
	}

	return ready
}

func (b *OrderedBuffer) Flush() []types.TaskResult {
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

	results := make([]types.TaskResult, len(indices))
	for i, idx := range indices {
		results[i] = b.results[idx]
	}

	clear(b.results)
	b.next = 0

	return results
}
