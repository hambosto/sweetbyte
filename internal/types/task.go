package types

// Task represents a processing task for concurrent operations.
type Task struct {
	Data  []byte
	Index uint64
}

// TaskResult represents the result of a processed task.
type TaskResult struct {
	Index uint64
	Data  []byte
	Size  int
	Err   error
}
