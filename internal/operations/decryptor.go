package operations

import (
	"context"
	"fmt"
	"math"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/files"
	"github.com/hambosto/sweetbyte/internal/header"
	"github.com/hambosto/sweetbyte/internal/keys"
	"github.com/hambosto/sweetbyte/internal/options"
	"github.com/hambosto/sweetbyte/internal/streaming"
)

// Decryptor handles file decryption operations
type Decryptor struct {
	fileManager *files.Manager
	fileFinder  *files.Finder
}

// NewDecryptor creates a new decryptor instance
func NewDecryptor() *Decryptor {
	return &Decryptor{
		fileManager: files.NewManager(),
		fileFinder:  files.NewFinder(),
	}
}

// DecryptFile decrypts a file from source to destination
func (d *Decryptor) DecryptFile(srcPath, destPath, password string) error {
	// Open source file
	srcFile, _, err := d.fileManager.OpenFile(srcPath)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close() //nolint:errcheck

	// Read and parse header
	header, err := header.Read(srcFile)
	if err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}

	// Derive key from password and verify
	key, err := keys.Hash([]byte(password), header.Salt())
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}

	if err := header.Verify(key); err != nil {
		return fmt.Errorf("header verification failed: %w", err)
	}

	fmt.Printf("Header verified successfully!\n")
	fmt.Printf("Original size: %d bytes\n", header.OriginalSize())
	fmt.Printf("Version: %d\n", header.Version())
	fmt.Printf("Security flags: %v\n", header.Flags())

	// Validate original size
	originalSize := header.OriginalSize()
	if originalSize > math.MaxInt64 {
		return fmt.Errorf("file too large: %d bytes", originalSize)
	}

	// Create destination file
	destFile, err := d.fileManager.CreateFile(destPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer destFile.Close() //nolint:errcheck

	// Create stream processor for decryption
	config := streaming.StreamConfig{
		Key:         key,
		Processing:  options.Decryption,
		Concurrency: config.MaxConcurrency,
		ChunkSize:   config.DefaultChunkSize,
	}

	processor, err := streaming.NewStreamProcessor(config)
	if err != nil {
		return fmt.Errorf("failed to create stream processor: %w", err)
	}

	// Process the file (remaining data after header)
	return processor.Process(context.Background(), srcFile, destFile, int64(originalSize))
}
