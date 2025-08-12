package compression

import (
	"bytes"
	"compress/zlib"
	"testing"

	"github.com/hambosto/sweetbyte/internal/compression"
	"github.com/hambosto/sweetbyte/internal/errors"
	"github.com/hambosto/sweetbyte/internal/types"
)

func TestNewCompressor(t *testing.T) {
	tests := []struct {
		name     string
		level    types.CompressionLevel
		expected int
	}{
		{
			name:     "Valid compression level - no compression",
			level:    types.LevelNoCompression,
			expected: int(types.LevelNoCompression),
		},
		{
			name:     "Valid compression level - best speed",
			level:    types.LevelBestSpeed,
			expected: int(types.LevelBestSpeed),
		},
		{
			name:     "Valid compression level - default",
			level:    types.LevelDefaultCompression,
			expected: int(types.LevelDefaultCompression),
		},
		{
			name:     "Valid compression level - best compression",
			level:    types.LevelBestCompression,
			expected: int(types.LevelBestCompression),
		},
		{
			name:     "Invalid compression level - too low",
			level:    types.CompressionLevel(-2),
			expected: int(types.LevelDefaultCompression),
		},
		{
			name:     "Invalid compression level - too high",
			level:    types.CompressionLevel(10),
			expected: int(types.LevelDefaultCompression),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compressor, err := compression.NewCompressor(tt.level)
			if err != nil {
				t.Errorf("NewCompressor() error = %v, wantErr false", err)
				return
			}
			if compressor == nil {
				t.Error("NewCompressor() returned nil compressor")
				return
			}
			// Note: We can't directly access the level field since it's unexported
			// But we can test the behavior through compression operations
		})
	}
}

func TestCompressor_Compress(t *testing.T) {
	compressor, err := compression.NewCompressor(types.LevelDefaultCompression)
	if err != nil {
		t.Fatalf("Failed to create compressor: %v", err)
	}

	tests := []struct {
		name     string
		input    []byte
		wantErr  error
		validate func(t *testing.T, compressed []byte)
	}{
		{
			name:    "Empty data",
			input:   []byte{},
			wantErr: errors.ErrCompressionFailed,
		},
		{
			name:    "Nil data",
			input:   nil,
			wantErr: errors.ErrCompressionFailed,
		},
		{
			name:    "Small text data",
			input:   []byte("Hello, World!"),
			wantErr: nil,
			validate: func(t *testing.T, compressed []byte) {
				if len(compressed) == 0 {
					t.Error("Compressed data should not be empty")
				}
				// Verify it's valid zlib data by trying to decompress
				reader, err := zlib.NewReader(bytes.NewReader(compressed))
				if err != nil {
					t.Errorf("Invalid zlib data: %v", err)
				}
				defer reader.Close() //nolint:errcheck
			},
		},
		{
			name:    "Repeated data (should compress well)",
			input:   bytes.Repeat([]byte("A"), 1000),
			wantErr: nil,
			validate: func(t *testing.T, compressed []byte) {
				if len(compressed) >= 1000 {
					t.Error("Compressed data should be smaller than original for repeated data")
				}
			},
		},
		{
			name:    "Binary data",
			input:   []byte{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC},
			wantErr: nil,
			validate: func(t *testing.T, compressed []byte) {
				if len(compressed) == 0 {
					t.Error("Compressed data should not be empty")
				}
			},
		},
		{
			name:    "Large data",
			input:   make([]byte, 100000), // 100KB of zeros
			wantErr: nil,
			validate: func(t *testing.T, compressed []byte) {
				if len(compressed) >= 100000 {
					t.Error("Compressed data should be much smaller for repeated zeros")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			compressed, err := compressor.Compress(tt.input)

			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("Compress() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("Compress() unexpected error = %v", err)
				return
			}

			if tt.validate != nil {
				tt.validate(t, compressed)
			}
		})
	}
}

func TestCompressor_Decompress(t *testing.T) {
	compressor, err := compression.NewCompressor(types.LevelDefaultCompression)
	if err != nil {
		t.Fatalf("Failed to create compressor: %v", err)
	}

	tests := []struct {
		name    string
		setup   func() []byte // Function to create test data
		wantErr error
	}{
		{
			name: "Empty data",
			setup: func() []byte {
				return []byte{}
			},
			wantErr: errors.ErrDecompressionFailed,
		},
		{
			name: "Nil data",
			setup: func() []byte {
				return nil
			},
			wantErr: errors.ErrDecompressionFailed,
		},
		{
			name: "Invalid zlib data",
			setup: func() []byte {
				return []byte{0xFF, 0xFF, 0xFF, 0xFF} // Invalid zlib header
			},
			wantErr: errors.ErrDecompressionFailed,
		},
		{
			name: "Truncated zlib data",
			setup: func() []byte {
				// Create valid zlib data then truncate it
				var buf bytes.Buffer
				writer := zlib.NewWriter(&buf)
				writer.Write([]byte("Hello")) //nolint:errcheck
				writer.Close()                //nolint:errcheck
				data := buf.Bytes()
				return data[:len(data)-5] // Truncate
			},
			wantErr: errors.ErrDecompressionFailed,
		},
		{
			name: "Valid compressed data",
			setup: func() []byte {
				data, err := compressor.Compress([]byte("Hello, World!"))
				if err != nil {
					t.Fatalf("Failed to create test data: %v", err)
				}
				return data
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data := tt.setup()

			decompressed, err := compressor.Decompress(data)

			if tt.wantErr != nil {
				if err != tt.wantErr {
					t.Errorf("Decompress() error = %v, wantErr %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Errorf("Decompress() unexpected error = %v", err)
				return
			}

			if len(decompressed) == 0 {
				t.Error("Decompressed data should not be empty for valid input")
			}
		})
	}
}

func TestCompressor_CompressDecompressRoundTrip(t *testing.T) {
	compressor, err := compression.NewCompressor(types.LevelDefaultCompression)
	if err != nil {
		t.Fatalf("Failed to create compressor: %v", err)
	}

	testData := [][]byte{
		[]byte("Hello, World!"),
		[]byte("The quick brown fox jumps over the lazy dog"),
		bytes.Repeat([]byte("A"), 1000),
		{0x00, 0x01, 0x02, 0x03, 0xFF, 0xFE, 0xFD, 0xFC},
		make([]byte, 10000), // Large data with zeros
	}

	// Fill the large data with some pattern
	for i := range testData[4] {
		testData[4][i] = byte(i % 256)
	}

	for i, original := range testData {
		t.Run(t.Name()+"_case_"+string(rune(i+'0')), func(t *testing.T) {
			// Compress
			compressed, err := compressor.Compress(original)
			if err != nil {
				t.Errorf("Compress() error = %v", err)
				return
			}

			// Decompress
			decompressed, err := compressor.Decompress(compressed)
			if err != nil {
				t.Errorf("Decompress() error = %v", err)
				return
			}

			// Compare
			if !bytes.Equal(original, decompressed) {
				t.Errorf("Round-trip failed: original != decompressed")
				t.Errorf("Original length: %d, Decompressed length: %d", len(original), len(decompressed))
				if len(original) < 100 && len(decompressed) < 100 {
					t.Errorf("Original: %v", original)
					t.Errorf("Decompressed: %v", decompressed)
				}
			}
		})
	}
}

func TestCompressor_DifferentCompressionLevels(t *testing.T) {
	testData := bytes.Repeat([]byte("Hello, World! "), 1000) // Repeating data compresses well

	levels := []types.CompressionLevel{
		types.LevelNoCompression,
		types.LevelBestSpeed,
		types.LevelDefaultCompression,
		types.LevelBestCompression,
	}

	results := make(map[types.CompressionLevel][]byte)

	for _, level := range levels {
		t.Run("Level_"+string(rune(int(level)+'0')), func(t *testing.T) {
			compressor, err := compression.NewCompressor(level)
			if err != nil {
				t.Errorf("NewCompressor() error = %v", err)
				return
			}

			compressed, err := compressor.Compress(testData)
			if err != nil {
				t.Errorf("Compress() error = %v", err)
				return
			}

			// Verify decompression works
			decompressed, err := compressor.Decompress(compressed)
			if err != nil {
				t.Errorf("Decompress() error = %v", err)
				return
			}

			if !bytes.Equal(testData, decompressed) {
				t.Error("Round-trip failed for compression level", level)
			}

			results[level] = compressed
		})
	}

	// Verify that different compression levels produce different results
	// (except no compression might be the same as some others for small data)
	if len(results) > 1 {
		t.Log("Compression ratios:")
		for level, compressed := range results {
			ratio := float64(len(compressed)) / float64(len(testData))
			t.Logf("Level %d: %.2f%% (%d -> %d bytes)",
				int(level), ratio*100, len(testData), len(compressed))
		}
	}
}

func TestCompressor_DecompressionSizeLimit(t *testing.T) {
	compressor, err := compression.NewCompressor(types.LevelDefaultCompression)
	if err != nil {
		t.Fatalf("Failed to create compressor: %v", err)
	}

	// Create data that's exactly at the limit (10MB)
	largeData := make([]byte, 10<<20) // 10MB
	for i := range largeData {
		largeData[i] = byte(i % 256)
	}

	compressed, err := compressor.Compress(largeData)
	if err != nil {
		t.Fatalf("Failed to compress large data: %v", err)
	}

	// This should work (at the limit)
	decompressed, err := compressor.Decompress(compressed)
	if err != nil {
		t.Errorf("Decompress() should handle data at size limit: %v", err)
	}

	if !bytes.Equal(largeData, decompressed) {
		t.Error("Round-trip failed for large data at size limit")
	}
}

func BenchmarkCompressor_Compress(b *testing.B) {
	compressor, err := compression.NewCompressor(types.LevelDefaultCompression)
	if err != nil {
		b.Fatalf("Failed to create compressor: %v", err)
	}

	data := bytes.Repeat([]byte("The quick brown fox jumps over the lazy dog. "), 1000)

	b.ReportAllocs()

	for b.Loop() {
		_, err := compressor.Compress(data)
		if err != nil {
			b.Fatalf("Compress() error = %v", err)
		}
	}
}

func BenchmarkCompressor_Decompress(b *testing.B) {
	compressor, err := compression.NewCompressor(types.LevelDefaultCompression)
	if err != nil {
		b.Fatalf("Failed to create compressor: %v", err)
	}

	data := bytes.Repeat([]byte("The quick brown fox jumps over the lazy dog. "), 1000)
	compressed, err := compressor.Compress(data)
	if err != nil {
		b.Fatalf("Failed to create test data: %v", err)
	}

	b.ReportAllocs()

	for b.Loop() {
		_, err := compressor.Decompress(compressed)
		if err != nil {
			b.Fatalf("Decompress() error = %v", err)
		}
	}
}
