package padding

import (
	"bytes"
	"fmt"
)

const (
	BlockSize    = 128
	MaxBlockSize = 255
)

type Padding struct {
	blockSize int
}

func NewPadding(blockSize int) (*Padding, error) {
	if blockSize <= 0 || blockSize > MaxBlockSize {
		return nil, fmt.Errorf("block size must be between 1 and 255, got %d", blockSize)
	}
	return &Padding{blockSize: blockSize}, nil
}

func (p *Padding) Pad(data []byte) ([]byte, error) {
	if data == nil {
		return nil, fmt.Errorf("data cannot be nil")
	}

	paddingLen := p.blockSize - (len(data) % p.blockSize)
	padding := bytes.Repeat([]byte{byte(paddingLen)}, paddingLen)
	return append(data, padding...), nil
}

func (p *Padding) Unpad(data []byte) ([]byte, error) {
	if data == nil {
		return nil, fmt.Errorf("data cannot be nil")
	}

	dataLen := len(data)
	paddingLen := int(data[dataLen-1])
	return data[:dataLen-paddingLen], nil
}
