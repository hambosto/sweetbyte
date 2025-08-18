// Package operations provides high-level encryption and decryption operations.
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

// Decryptor handles the decryption of files.
type Decryptor struct {
	fileManager *files.Manager
	fileFinder  *files.Finder
}

// NewDecryptor creates a new Decryptor.
func NewDecryptor() *Decryptor {
	return &Decryptor{
		fileManager: files.NewManager(),
		fileFinder:  files.NewFinder(),
	}
}

// DecryptFile decrypts a file.
func (d *Decryptor) DecryptFile(srcPath, destPath, password string) error {
	// Open the source file.
	srcFile, _, err := d.fileManager.OpenFile(srcPath)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close()

	// Read the header from the source file.
	header, err := header.Read(srcFile)
	if err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}

	// Derive the key from the password and salt.
	key, err := keys.Hash([]byte(password), header.Salt())
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}

	// Verify the header.
	if err := header.Verify(key); err != nil {
		return fmt.Errorf("decryption failed: incorrect password or corrupt file: %w", err)
	}

	// Get the original size of the file from the header.
	originalSize := header.OriginalSize()
	if originalSize > math.MaxInt64 {
		return fmt.Errorf("file too large: %d bytes", originalSize)
	}

	// Create the destination file.
	destFile, err := d.fileManager.CreateFile(destPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer destFile.Close()

	// Create a new stream processor for decryption.
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

	// Process the file.
	if err := processor.Process(context.Background(), srcFile, destFile, int64(originalSize)); err != nil {
		return fmt.Errorf("failed to process file: %w", err)
	}

	return nil
}
