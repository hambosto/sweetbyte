package compression

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
)

// CompressionLevel represents compression levels.
type CompressionLevel int

const (
	// LevelNoCompression disables compression.
	LevelNoCompression CompressionLevel = iota
	// LevelBestSpeed provides fastest compression.
	LevelBestSpeed
	// LevelDefaultCompression provides balanced compression.
	LevelDefaultCompression
	// LevelBestCompression provides maximum compression.
	LevelBestCompression
)

// Compressor handles data compression and decompression using zlib
type Compressor struct {
	level int
}

// NewCompressor creates a new compressor with the specified compression level
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

// Compress compresses the input data using zlib
func (c *Compressor) Compress(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("compression failed: empty data")
	}

	var buf bytes.Buffer
	// Create zlib writer with specified compression level
	writer, err := zlib.NewWriterLevel(&buf, c.level)
	if err != nil {
		return nil, fmt.Errorf("compression failed: %w", err)
	}
	defer writer.Close() //nolint:errcheck

	// Write data to compressor
	if _, err := writer.Write(data); err != nil {
		return nil, fmt.Errorf("compression failed: %w", err)
	}

	// Close writer to flush remaining data
	if err := writer.Close(); err != nil {
		return nil, fmt.Errorf("compression failed: %w", err)
	}

	return buf.Bytes(), nil
}

// Decompress decompresses the input data using zlib
func (c *Compressor) Decompress(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("decompression failed: empty data")
	}

	// Create reader from compressed data
	reader, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("decompression failed: %w", err)
	}
	defer reader.Close() //nolint:errcheck

	// Read decompressed data
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, reader); err != nil {
		return nil, fmt.Errorf("decompression failed: %w", err)
	}

	return buf.Bytes(), nil
}
