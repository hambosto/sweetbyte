// Package compression provides zlib compression and decompression functionalities.
package compression

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
)

// Level defines the compression level.
type Level int

const (
	// LevelNoCompression provides no compression.
	LevelNoCompression Level = iota
	// LevelBestSpeed provides the fastest compression.
	LevelBestSpeed
	// LevelDefaultCompression provides the default compression level.
	LevelDefaultCompression
	// LevelBestCompression provides the best compression.
	LevelBestCompression
)

// Compressor defines the interface for compression and decompression.
type Compressor interface {
	// Compress compresses the given data.
	Compress(data []byte) ([]byte, error)
	// Decompress decompress a given data.
	Decompress(data []byte) ([]byte, error)
}

// compressor implements the Compressor interface using zlib.
type compressor struct {
	level int
}

// NewCompressor creates a new Compressor with the given compression level.
func NewCompressor(level Level) (Compressor, error) {
	var zlibLevel int

	// Map the custom compression level to the zlib compression level.
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

// Compress compresses the given data using the configured zlib compression level.
func (c *compressor) Compress(data []byte) ([]byte, error) {
	// Ensure data is not empty.
	if len(data) == 0 {
		return nil, fmt.Errorf("data cannot be empty")
	}

	// Create a new zlib writer.
	var buf bytes.Buffer
	writer, err := zlib.NewWriterLevel(&buf, c.level)
	if err != nil {
		return nil, fmt.Errorf("failed to create compressor: %w", err)
	}

	// Write data to the writer to compress it.
	if _, err := writer.Write(data); err != nil {
		return nil, fmt.Errorf("failed to compress data: %w", err)
	}

	// Close the writer to finalize the compression.
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to finalize compression: %w", err)
	}

	return buf.Bytes(), nil
}

// Decompress decompresses the given data.
func (c *compressor) Decompress(data []byte) ([]byte, error) {
	// Ensure data is not empty.
	if len(data) == 0 {
		return nil, fmt.Errorf("data cannot be empty")
	}

	// Create a new zlib reader.
	reader, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create decompressor: %w", err)
	}

	// Read the decompressed data from the reader.
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, io.LimitReader(reader, 10<<20)); err != nil {
		return nil, fmt.Errorf("failed to decompress data: %w", err)
	}

	// Close the reader.
	if err := reader.Close(); err != nil {
		return nil, fmt.Errorf("failed to finalize decompression: %w", err)
	}

	return buf.Bytes(), nil
}
