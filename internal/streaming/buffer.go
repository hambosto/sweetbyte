package streaming

import (
	"slices"

	"github.com/hambosto/sweetbyte/internal/types"
)

// Buffer holds task results and ensures they are emitted in order based on their index
type Buffer struct {
	results map[uint64]types.TaskResult // Stores task results by their index
	next    uint64                      // The next expected index to return in order
}

// NewBuffer creates and returns a new Buffer instance
func NewBuffer() *Buffer {
	return &Buffer{
		results: make(map[uint64]types.TaskResult),
		next:    0,
	}
}

// Add inserts a TaskResult into the buffer and returns all ready-to-process results
// in the correct order starting from the current 'next' index
func (b *Buffer) Add(result types.TaskResult) []types.TaskResult {
	b.results[result.Index] = result

	var ready []types.TaskResult
	for {
		// Emit results in order as long as the next expected index is available
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

// Flush returns all remaining buffered TaskResults sorted by index
// This is typically called when all input has been processed and
// no more results are expected
func (b *Buffer) Flush() []types.TaskResult {
	if len(b.results) == 0 {
		return nil
	}

	// Collect and sort remaining indices
	indices := make([]uint64, 0, len(b.results))
	for idx := range b.results {
		indices = append(indices, idx)
	}
	slices.Sort(indices)

	// Build ordered result slice
	results := make([]types.TaskResult, len(indices))
	for i, idx := range indices {
		results[i] = b.results[idx]
	}

	// Clear the buffer
	b.results = make(map[uint64]types.TaskResult)

	return results
}
