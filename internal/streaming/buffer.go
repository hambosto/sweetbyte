package streaming

import (
	"slices"
	"sync"

	"github.com/hambosto/sweetbyte/internal/types"
)

// orderBuffer maintains chunk ordering for concurrent processing
type orderBuffer struct {
	mu      sync.Mutex
	results map[uint64]types.TaskResult
	next    uint64
}

// NewOrderBuffer creates a new thread-safe order buffer
func NewOrderBuffer() OrderBuffer {
	return &orderBuffer{
		results: make(map[uint64]types.TaskResult),
		next:    0,
	}
}

// Add inserts a result and returns any ready results in order
func (b *orderBuffer) Add(result types.TaskResult) []types.TaskResult {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.results[result.Index] = result

	var ready []types.TaskResult
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

// Flush returns all remaining buffered results sorted by index
func (b *orderBuffer) Flush() []types.TaskResult {
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

	// Clear the buffer
	clear(b.results)

	return results
}
