package types

type Task struct {
	Data  []byte
	Index uint64
}

type TaskResult struct {
	Index uint64
	Data  []byte
	Size  int
	Err   error
}
