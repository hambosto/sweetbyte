package padding

import (
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

	padding := p.blockSize - (len(data) % p.blockSize)
	padText := make([]byte, padding)
	for i := range padText {
		padText[i] = byte(padding)
	}

	return append(data, padText...), nil
}

func (p *padding) Unpad(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data cannot be empty")
	}

	if len(data)%p.blockSize != 0 {
		return nil, fmt.Errorf("data length must be multiple of block size %d, got %d", p.blockSize, len(data))
	}

	padding := int(data[len(data)-1])
	if padding == 0 || padding > p.blockSize {
		return nil, fmt.Errorf("padding value must be between 1 and %d, got %d", p.blockSize, padding)
	}

	if padding > len(data) {
		return nil, fmt.Errorf("padding value %d exceeds data length %d", padding, len(data))
	}

	for i := len(data) - padding; i < len(data); i++ {
		if data[i] != byte(padding) {
			return nil, fmt.Errorf("invalid padding byte at position %d, expected %d got %d", i, padding, data[i])
		}
	}

	return data[:len(data)-padding], nil
}
