// Package streaming provides functionalities for streaming data processing.
package streaming

import (
	"slices"
	"sync"
)

// OrderBuffer defines the interface for a buffer that maintains the order of task results.
type OrderBuffer interface {
	// Add adds a task result to the buffer and returns any results that are now in order.
	Add(result TaskResult) []TaskResult
	// Flush returns all remaining results in the buffer, in order.
	Flush() []TaskResult
}

// orderBuffer implements the OrderBuffer interface.
type orderBuffer struct {
	mu      sync.Mutex
	results map[uint64]TaskResult
	next    uint64
}

// NewOrderBuffer creates a new OrderBuffer.
func NewOrderBuffer() OrderBuffer {
	return &orderBuffer{
		results: make(map[uint64]TaskResult),
		next:    0,
	}
}

// Add adds a task result to the buffer and returns any results that are now in order.
func (b *orderBuffer) Add(result TaskResult) []TaskResult {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Add the result to the map.
	b.results[result.Index] = result
	var ready []TaskResult

	// Check for any in-order results that are now ready.
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

// Flush returns all remaining results in the buffer, in order.
func (b *orderBuffer) Flush() []TaskResult {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.results) == 0 {
		return nil
	}

	// Get all the indices from the map.
	indices := make([]uint64, 0, len(b.results))
	for idx := range b.results {
		indices = append(indices, idx)
	}

	// Sort the indices to ensure the results are in order.
	slices.Sort(indices)
	// Create a slice of results in the correct order.
	results := make([]TaskResult, len(indices))
	for i, idx := range indices {
		results[i] = b.results[idx]
	}

	// Clear the map.
	clear(b.results)
	return results
}
