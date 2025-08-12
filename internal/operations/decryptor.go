package operations

import (
	"fmt"
	"math"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/errors"
	"github.com/hambosto/sweetbyte/internal/files"
	"github.com/hambosto/sweetbyte/internal/header"
	"github.com/hambosto/sweetbyte/internal/keys"
	"github.com/hambosto/sweetbyte/internal/streaming"
	"github.com/hambosto/sweetbyte/internal/types"
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
	header, err := header.ReadFrom(srcFile)
	if err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}

	// Derive key from password and verify
	key, err := keys.Hash([]byte(password), header.Salt())
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}

	if err := header.Verify(key); err != nil {
		switch err {
		case errors.ErrAuthFailure:
			return fmt.Errorf("%w: wrong key or tampered auth tag", err)
		case errors.ErrIntegrityFailure:
			return fmt.Errorf("%w: header structure corrupted", err)
		case errors.ErrChecksumMismatch:
			return fmt.Errorf("%w: data corruption detected", err)
		}
	}

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
		Processing:  types.Decryption,
		Concurrency: config.MaxConcurrency,
		QueueSize:   config.QueueSize,
		ChunkSize:   config.DefaultChunkSize,
	}

	processor, err := streaming.NewStreamProcessor(config)
	if err != nil {
		return fmt.Errorf("failed to create stream processor: %w", err)
	}

	// Process the file (remaining data after header)
	return processor.Process(srcFile, destFile, int64(originalSize))
}
