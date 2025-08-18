// Package compression provides data compression and decompression functionality.
package compression

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
)

// CompressionLevel defines the level of compression to be used.
type CompressionLevel int

const (
	// LevelNoCompression disables compression.
	LevelNoCompression CompressionLevel = iota
	// LevelBestSpeed provides the fastest compression.
	LevelBestSpeed
	// LevelDefaultCompression provides the default compression level.
	LevelDefaultCompression
	// LevelBestCompression provides the best compression.
	LevelBestCompression
)

// Compressor handles data compression and decompression.
type Compressor struct {
	level int
}

// NewCompressor creates a new Compressor with the specified compression level.
func NewCompressor(level CompressionLevel) (*Compressor, error) {
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

	return &Compressor{level: zlibLevel}, nil
}

// Compress compresses the given data.
func (c *Compressor) Compress(data []byte) ([]byte, error) {
	// Data cannot be empty.
	if len(data) == 0 {
		return nil, fmt.Errorf("data cannot be empty")
	}

	// Create a new buffer and a zlib writer.
	var buf bytes.Buffer
	writer, err := zlib.NewWriterLevel(&buf, c.level)
	if err != nil {
		return nil, fmt.Errorf("failed to create compressor: %w", err)
	}

	// Write the data to the writer.
	if _, err := writer.Write(data); err != nil {
		return nil, fmt.Errorf("failed to compress data: %w", err)
	}

	// Close the writer to finalize compression.
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to finalize compression: %w", err)
	}

	return buf.Bytes(), nil
}

// Decompress decompress the given data.
func (c *Compressor) Decompress(data []byte) ([]byte, error) {
	// Data cannot be empty.
	if len(data) == 0 {
		return nil, fmt.Errorf("data cannot be empty")
	}

	// Create a new zlib reader.
	reader, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create decompressor: %w", err)
	}

	// Copy the decompressed data to a buffer.
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, reader); err != nil {
		return nil, fmt.Errorf("failed to decompress data: %w", err)
	}

	// Close the reader to finalize decompression.
	if err := reader.Close(); err != nil {
		return nil, fmt.Errorf("failed to finalize decompression: %w", err)
	}

	return buf.Bytes(), nil
}
