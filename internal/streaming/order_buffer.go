// Package streaming provides the infrastructure for efficient, chunk-based file processing.
// It includes components for reading, processing, and writing data in a streaming fashion,
// utilizing concurrency for performance and managing the order of processed chunks.
package streaming

import (
	"slices"
	"sync"
)

// orderBuffer implements the OrderBuffer interface.
// It temporarily stores TaskResults that arrive out of order and releases them
// in the correct sequence as their preceding chunks become available.
type orderBuffer struct {
	mu      sync.Mutex            // Mutex to protect concurrent access to the buffer.
	results map[uint64]TaskResult // Map to store results, keyed by their index.
	next    uint64                // The index of the next expected chunk.
}

// NewOrderBuffer creates and returns a new OrderBuffer instance.
// It initializes the internal map and sets the next expected index to 0.
func NewOrderBuffer() OrderBuffer {
	return &orderBuffer{
		results: make(map[uint64]TaskResult), // Initialize the map to store results.
		next:    0,                           // Start expecting chunk with index 0.
	}
}

// Add a TaskResult to the buffer and returns any contiguous sequence of TaskResults
// that are now in order, starting from the `next` expected index.
// It acquires a lock to ensure thread-safe operations on the buffer.
func (b *orderBuffer) Add(result TaskResult) []TaskResult {
	b.mu.Lock()         // Acquire a lock to protect shared state.
	defer b.mu.Unlock() // Ensure the lock is released when the function exits.

	b.results[result.Index] = result // Store the incoming result in the map using its index.

	var ready []TaskResult // Slice to hold results that are now in order.
	for {                  // Loop to collect all contiguous, in-order results.
		if result, exists := b.results[b.next]; exists { // Check if the next expected result is available.
			ready = append(ready, result) // Add the ready result to the slice.
			delete(b.results, b.next)     // Remove the result from the buffer.
			b.next++                      // Increment the next expected index.
		} else {
			break // Break the loop if the next expected result is not found (gap in sequence).
		}
	}

	return ready // Return the slice of ready (in-order) results.
}

// Flush returns all remaining TaskResults in the buffer, regardless of their order.
// This is typically called at the end of the stream to ensure all data is processed.
// Results are sorted by their index before being returned.
func (b *orderBuffer) Flush() []TaskResult {
	b.mu.Lock()         // Acquire a lock to protect shared state.
	defer b.mu.Unlock() // Ensure the lock is released when the function exits.

	if len(b.results) == 0 { // If the buffer is empty, there's nothing to flush.
		return nil
	}

	indices := make([]uint64, 0, len(b.results)) // Create a slice to store all available indices.
	for idx := range b.results {                 // Populate the indices slice.
		indices = append(indices, idx)
	}

	slices.Sort(indices)                        // Sort the indices to retrieve results in order.
	results := make([]TaskResult, len(indices)) // Create a slice to hold the sorted results.
	for i, idx := range indices {               // Populate the results slice based on sorted indices.
		results[i] = b.results[idx]
	}

	clear(b.results) // Clear the internal map after flushing.
	return results   // Return the sorted remaining results.
}
