package padding

import (
	"bytes"
	"fmt"
)

type Padding struct {
	blockSize int
}

func NewPadding(blockSize int) (*Padding, error) {
	if blockSize <= 0 || blockSize > 255 {
		return nil, fmt.Errorf("block size must be between 1 and 255, got %d", blockSize)
	}
	return &Padding{
		blockSize: blockSize,
	}, nil
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
	dataLen := len(data)

	if dataLen == 0 {
		return nil, fmt.Errorf("data too short to contain valid padding")
	}

	paddingLen := int(data[dataLen-1])
	if paddingLen == 0 || paddingLen > p.blockSize {
		return nil, fmt.Errorf("invalid padding length %d for block size %d", paddingLen, p.blockSize)
	}

	if paddingLen > dataLen {
		return nil, fmt.Errorf("padding length %d exceeds data length %d", paddingLen, dataLen)
	}

	for i := dataLen - paddingLen; i < dataLen; i++ {
		if data[i] != byte(paddingLen) {
			return nil, fmt.Errorf("invalid padding byte at position %d: expected %d, got %d", i, paddingLen, data[i])
		}
	}

	result := make([]byte, dataLen-paddingLen)
	copy(result, data[:dataLen-paddingLen])
	return result, nil
}
