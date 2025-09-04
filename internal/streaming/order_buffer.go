// Package streaming provides the core functionality for streaming encryption and decryption.
package streaming

import (
	"slices"
	"sync"
)

// OrderBuffer is a buffer that stores and retrieves task results in order.
type OrderBuffer interface {
	Add(result TaskResult) []TaskResult
	Flush() []TaskResult
}

// orderBuffer is a buffer that stores and retrieves task results in order.
type orderBuffer struct {
	mu      sync.Mutex
	results map[uint64]TaskResult
	next    uint64
}

// NewOrderBuffer creates a new orderBuffer.
func NewOrderBuffer() OrderBuffer {
	return &orderBuffer{
		results: make(map[uint64]TaskResult),
		next:    0,
	}
}

// Add adds a task result to the buffer and returns any ready results.
func (b *orderBuffer) Add(result TaskResult) []TaskResult {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Add the result to the map.
	b.results[result.Index] = result
	var ready []TaskResult
	// Check for consecutive results starting from the next expected index.
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

// Flush returns any remaining results in the buffer, in order.
func (b *orderBuffer) Flush() []TaskResult {
	b.mu.Lock()
	defer b.mu.Unlock()

	// If the buffer is empty, return nil.
	if len(b.results) == 0 {
		return nil
	}

	// Get the indices of the remaining results.
	indices := make([]uint64, 0, len(b.results))
	for idx := range b.results {
		indices = append(indices, idx)
	}

	// Sort the indices to ensure the results are in order.
	slices.Sort(indices)
	results := make([]TaskResult, len(indices))
	for i, idx := range indices {
		results[i] = b.results[idx]
	}

	// Clear the buffer.
	clear(b.results)
	return results
}
