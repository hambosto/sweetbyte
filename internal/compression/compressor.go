// Package compression provides utilities for compressing and decompressing data
// using the Zlib compression algorithm. It offers different compression levels
// to balance between compression ratio and speed.
package compression

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"io"
)

// CompressionLevel defines the strength of the Zlib compression.
type CompressionLevel int

const (
	// LevelNoCompression specifies no compression.
	LevelNoCompression CompressionLevel = iota
	// LevelBestSpeed specifies the fastest compression level.
	LevelBestSpeed
	// LevelDefaultCompression specifies the default compression level.
	LevelDefaultCompression
	// LevelBestCompression specifies the best compression ratio, potentially slower.
	LevelBestCompression
)

// Compressor handles compression and decompression operations using Zlib.
// It stores the configured compression level.
type Compressor struct {
	level int // The Zlib compression level (e.g., zlib.BestCompression).
}

// NewCompressor creates and returns a new Compressor instance.
// It maps the custom CompressionLevel to a zlib package constant.
func NewCompressor(level CompressionLevel) (*Compressor, error) {
	var zlibLevel int // Variable to hold the corresponding zlib package level.

	switch level { // Map the custom compression level to the zlib package's constant.
	case LevelNoCompression:
		zlibLevel = zlib.NoCompression
	case LevelBestSpeed:
		zlibLevel = zlib.BestSpeed
	case LevelDefaultCompression:
		zlibLevel = zlib.DefaultCompression
	case LevelBestCompression:
		zlibLevel = zlib.BestCompression
	default:
		zlibLevel = zlib.DefaultCompression // Default to DefaultCompression for unknown levels.
	}

	return &Compressor{level: zlibLevel}, nil // Return a new Compressor with the determined level.
}

// Compress applies Zlib compression to the input byte slice.
// It uses the configured compression level and returns the compressed data.
func (c *Compressor) Compress(data []byte) ([]byte, error) {
	if len(data) == 0 { // Check for empty input data.
		return nil, fmt.Errorf("data cannot be empty") // Return error if data is empty.
	}
	var buf bytes.Buffer // A buffer to write the compressed data to.

	writer, err := zlib.NewWriterLevel(&buf, c.level) // Create a new zlib writer with the specified level.
	if err != nil {
		return nil, fmt.Errorf("failed to create compressor: %w", err) // Handle error during writer creation.
	}

	if _, err := writer.Write(data); err != nil { // Write the input data to the zlib writer for compression.
		return nil, fmt.Errorf("failed to compress data: %w", err) // Handle error during data writing.
	}

	if err := writer.Close(); err != nil { // Close the writer to flush any buffered data and finalize compression.
		return nil, fmt.Errorf("failed to finalize compression: %w", err) // Handle error during writer closing.
	}

	return buf.Bytes(), nil // Return the compressed data from the buffer.
}

// Decompress decompresses a Zlib-compressed byte slice.
// It reads the compressed data and returns the original uncompressed byte slice.
func (c *Compressor) Decompress(data []byte) ([]byte, error) {
	if len(data) == 0 { // Check for empty input data.
		return nil, fmt.Errorf("data cannot be empty") // Return error if data is empty.
	}

	reader, err := zlib.NewReader(bytes.NewReader(data)) // Create a new zlib reader from the input compressed data.
	if err != nil {
		return nil, fmt.Errorf("failed to create decompressor: %w", err) // Handle error during reader creation.
	}

	var buf bytes.Buffer                             // A buffer to write the decompressed data to.
	if _, err := io.Copy(&buf, reader); err != nil { // Copy data from the decompressor to the buffer.
		return nil, fmt.Errorf("failed to decompress data: %w", err) // Handle error during data copying.
	}

	if err := reader.Close(); err != nil { // Close the reader to release resources.
		return nil, fmt.Errorf("failed to finalize decompression: %w", err) // Handle error during reader closing.
	}

	return buf.Bytes(), nil // Return the decompressed data from the buffer.
}
