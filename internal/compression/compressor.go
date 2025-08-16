package compression

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
)

// CompressionLevel defines the trade-off between compression speed and ratio.
type CompressionLevel int

const (
	// LevelNoCompression disables compression entirely.
	LevelNoCompression CompressionLevel = iota
	// LevelBestSpeed prioritizes speed over compression ratio.
	LevelBestSpeed
	// LevelDefaultCompression offers a balanced approach to speed and compression.
	LevelDefaultCompression
	// LevelBestCompression prioritizes the smallest possible output size.
	LevelBestCompression
)

// Compressor provides zlib-based data compression and decompression.
type Compressor struct {
	level int
}

// NewCompressor creates a new Compressor with a specified compression level.
func NewCompressor(level CompressionLevel) (*Compressor, error) {
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

	return &Compressor{level: zlibLevel}, nil
}

// Compress compresses a byte slice using the configured zlib compression level.
func (c *Compressor) Compress(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data cannot be empty")
	}

	var buf bytes.Buffer
	// Create zlib writer with specified compression level
	writer, err := zlib.NewWriterLevel(&buf, c.level)
	if err != nil {
		return nil, fmt.Errorf("failed to create compressor: %w", err)
	}

	// Write data to compressor
	if _, err := writer.Write(data); err != nil {
		return nil, fmt.Errorf("failed to compress data: %w", err)
	}

	// Close writer to flush remaining data
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("failed to finalize compression: %w", err)
	}

	return buf.Bytes(), nil
}

// Decompress decompresses a zlib-compressed byte slice.
func (c *Compressor) Decompress(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data cannot be empty")
	}

	// Create reader from compressed data
	reader, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("failed to create decompressor: %w", err)
	}

	// Read decompressed data
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, reader); err != nil {
		return nil, fmt.Errorf("failed to decompress data: %w", err)
	}

	// Close reader to check for integrity errors
	if err := reader.Close(); err != nil {
		return nil, fmt.Errorf("failed to finalize decompression: %w", err)
	}

	return buf.Bytes(), nil
}
