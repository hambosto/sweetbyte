package compression

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
)

type Level int

const (
	LevelNoCompression	Level	= iota

	LevelBestSpeed

	LevelDefaultCompression

	LevelBestCompression
)

type Compressor interface {
	Compress(data []byte) ([]byte, error)
	Decompress(data []byte) ([]byte, error)
}

type compressor struct {
	level int
}

func NewCompressor(level Level) (Compressor, error) {
	var zlibLevel int

	switch level {
	case LevelNoCompression:
		zlibLevel = zlib.NoCompression
	case LevelBestSpeed:
		zlibLevel = zlib.BestSpeed
	case LevelDefaultCompression:
		zlibLevel = zlib.DefaultCompression
	case LevelBestCompression:
		zlibLevel = zlib.BestCompression
	default:
		zlibLevel = zlib.DefaultCompression
	}

	return &compressor{level: zlibLevel}, nil
}

func (c *compressor) Compress(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data cannot be empty")
	}

	var buf bytes.Buffer
	writer, err := zlib.NewWriterLevel(&buf, c.level)
	if err != nil {
		return nil, fmt.Errorf("failed to create compressor: %w", err)
	}

	if _, err := writer.Write(data); err != nil {
		return nil, fmt.Errorf("failed to compress data: %w", err)
	}

	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to finalize compression: %w", err)
	}

	return buf.Bytes(), nil
}

func (c *compressor) Decompress(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data cannot be empty")
	}

	reader, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create decompressor: %w", err)
	}

	var buf bytes.Buffer
	if _, err := io.Copy(&buf, io.LimitReader(reader, 10<<20)); err != nil {
		return nil, fmt.Errorf("failed to decompress data: %w", err)
	}

	if err := reader.Close(); err != nil {
		return nil, fmt.Errorf("failed to finalize decompression: %w", err)
	}

	return buf.Bytes(), nil
}
