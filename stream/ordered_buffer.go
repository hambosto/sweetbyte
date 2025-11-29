package stream

import (
	"slices"
	"sync"

	"github.com/hambosto/sweetbyte/types"
)

// OrderedBuffer maintains task results in the correct sequence despite potentially
// out-of-order processing. It buffers results by index and releases them in order.
type OrderedBuffer struct {
	mu      sync.Mutex                  // Mutex to protect concurrent access to the buffer
	results map[uint64]types.TaskResult // Map of task results indexed by their position
	next    uint64                      // The next expected index in sequence
}

// NewOrderedBuffer creates and returns a new OrderedBuffer instance.
func NewOrderedBuffer() *OrderedBuffer {
	return &OrderedBuffer{
		results: make(map[uint64]types.TaskResult), // Initialize the results map
		next:    0,                                 // Start with index 0
	}
}

// Add adds a result to the buffer and returns any results that are ready to be written
// in the correct sequence order. It checks if the next expected index is available
// and releases all consecutive results in order.
func (b *OrderedBuffer) Add(result types.TaskResult) []types.TaskResult {
	b.mu.Lock()
	defer b.mu.Unlock()

	// Store the result with its index
	b.results[result.Index] = result
	var ready []types.TaskResult // Slice to hold results ready for writing

	// Check if the next expected result is available
	for {
		result, exists := b.results[b.next]
		if !exists {
			break // No more consecutive results available
		}
		// Add the result to ready list
		ready = append(ready, result)
		// Remove from buffer since it's ready to be written
		delete(b.results, b.next)
		b.next++ // Move to the next expected index
	}

	return ready
}

// Flush returns all remaining results in the buffer in index order and resets the buffer.
// This is typically called when no more results are expected, ensuring all remaining
// results are returned even if they're not in consecutive sequence.
func (b *OrderedBuffer) Flush() []types.TaskResult {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.results) == 0 {
		return nil // Return nil if no results remain
	}

	// Create a slice of indices to sort them
	indices := make([]uint64, 0, len(b.results))
	for idx := range b.results {
		indices = append(indices, idx) // Collect all indices
	}
	slices.Sort(indices) // Sort indices in ascending order

	// Create results slice in index order
	results := make([]types.TaskResult, len(indices))
	for i, idx := range indices {
		results[i] = b.results[idx] // Add results in sorted index order
	}

	// Clear the buffer and reset for future use
	clear(b.results) // Clear all entries from the map
	b.next = 0       // Reset the next expected index

	return results
}
