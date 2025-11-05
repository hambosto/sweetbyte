package padding

import (
	"bytes"
	"fmt"
)

type Padding interface {
	Pad(data []byte) ([]byte, error)
	Unpad(data []byte) ([]byte, error)
}

type padding struct {
	blockSize int
}

func NewPadding(blockSize int) (Padding, error) {
	if blockSize <= 0 || blockSize > 255 {
		return nil, fmt.Errorf("block size must be between 1 and 255, got %d", blockSize)
	}
	return &padding{
		blockSize: blockSize,
	}, nil
}

func (p *padding) Pad(data []byte) ([]byte, error) {
	if data == nil {
		return nil, fmt.Errorf("data cannot be nil")
	}

	paddingLen := p.blockSize - (len(data) % p.blockSize)
	padding := bytes.Repeat([]byte{byte(paddingLen)}, paddingLen)
	return append(data, padding...), nil
}

func (p *padding) Unpad(data []byte) ([]byte, error) {
	dataLen := len(data)

	if dataLen == 0 {
		return nil, fmt.Errorf("cannot unpad empty data")
	}

	if dataLen%p.blockSize != 0 {
		return nil, fmt.Errorf("data length %d is not a multiple of block size %d", dataLen, p.blockSize)
	}

	paddingLen := int(data[dataLen-1])
	if paddingLen == 0 || paddingLen > p.blockSize {
		return nil, fmt.Errorf("invalid padding length %d, must be between 1 and %d", paddingLen, p.blockSize)
	}

	if paddingLen > dataLen {
		return nil, fmt.Errorf("padding length %d exceeds data length %d", paddingLen, dataLen)
	}

	paddingStart := dataLen - paddingLen
	paddingBytes := data[paddingStart:]
	var invalid byte = 0
	for _, b := range paddingBytes {
		invalid |= b ^ byte(paddingLen)
	}
	if invalid != 0 {
		return nil, fmt.Errorf("invalid padding bytes")
	}

	return data[:paddingStart], nil
}
