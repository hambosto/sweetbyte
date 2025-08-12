package compression

import (
	"bytes"
	"compress/zlib"
	"io"

	"github.com/hambosto/sweetbyte/internal/errors"
	"github.com/hambosto/sweetbyte/internal/types"
)

// Compressor handles data compression and decompression using zlib
type Compressor struct {
	level int
}

// NewCompressor creates a new compressor with the specified compression level
func NewCompressor(level types.CompressionLevel) (*Compressor, error) {
	// Validate compression level
	if level < types.LevelNoCompression || level > types.LevelBestCompression {
		level = types.LevelDefaultCompression
	}

	return &Compressor{level: int(level)}, nil
}

// Compress compresses the input data using zlib
func (c *Compressor) Compress(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.ErrCompressionFailed
	}

	var buf bytes.Buffer

	// Create zlib writer with specified compression level
	writer, err := zlib.NewWriterLevel(&buf, c.level)
	if err != nil {
		return nil, errors.ErrCompressionFailed
	}
	defer writer.Close() //nolint:errcheck

	// Write data to compressor
	if _, err := writer.Write(data); err != nil {
		return nil, errors.ErrCompressionFailed
	}

	// Close writer to flush remaining data
	if err := writer.Close(); err != nil {
		return nil, errors.ErrCompressionFailed
	}

	return buf.Bytes(), nil
}

// Decompress decompresses the input data using zlib
func (c *Compressor) Decompress(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, errors.ErrDecompressionFailed
	}

	// Create reader from compressed data
	reader, err := zlib.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, errors.ErrDecompressionFailed
	}
	defer reader.Close() //nolint:errcheck

	limitReader := io.LimitReader(reader, 10<<20)

	// Read decompressed data
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, limitReader); err != nil {
		return nil, errors.ErrDecompressionFailed
	}

	return buf.Bytes(), nil
}
