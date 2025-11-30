package stream

import (
	"slices"
	"sync"

	"github.com/hambosto/sweetbyte/internal/types"
)

type OrderedBuffer struct {
	mu      sync.Mutex
	buffer  map[uint64]types.TaskResult
	nextIdx uint64
}

func NewOrderedBuffer() *OrderedBuffer {
	return &OrderedBuffer{
		buffer:  make(map[uint64]types.TaskResult),
		nextIdx: 0,
	}
}

func (b *OrderedBuffer) Add(result types.TaskResult) []types.TaskResult {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.buffer[result.Index] = result

	var ready []types.TaskResult
	for {
		result, exists := b.buffer[b.nextIdx]
		if !exists {
			break
		}
		ready = append(ready, result)
		delete(b.buffer, b.nextIdx)
		b.nextIdx++
	}

	return ready
}

func (b *OrderedBuffer) Flush() []types.TaskResult {
	b.mu.Lock()
	defer b.mu.Unlock()

	if len(b.buffer) == 0 {
		return nil
	}

	indices := make([]uint64, 0, len(b.buffer))
	for idx := range b.buffer {
		indices = append(indices, idx)
	}
	slices.Sort(indices)

	results := make([]types.TaskResult, len(indices))
	for i, idx := range indices {
		results[i] = b.buffer[idx]
	}

	clear(b.buffer)
	b.nextIdx = 0

	return results
}
