package operations

import (
	"context"
	"fmt"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/files"
	"github.com/hambosto/sweetbyte/internal/header"
	"github.com/hambosto/sweetbyte/internal/keys"
	"github.com/hambosto/sweetbyte/internal/options"
	"github.com/hambosto/sweetbyte/internal/streaming"
)

// Encryptor orchestrates the file encryption process.
// It manages file I/O, key derivation, header creation, and stream processing.
type Encryptor struct {
	fileManager *files.Manager
	fileFinder  *files.Finder
}

// NewEncryptor creates and initializes a new Encryptor instance.
func NewEncryptor() *Encryptor {
	return &Encryptor{
		fileManager: files.NewManager(),
		fileFinder:  files.NewFinder(),
	}
}

// EncryptFile performs the end-to-end encryption of a single file.
// It handles everything from opening the source and destination files
// to deriving the encryption key, writing the secure header, and processing
// the file content in concurrent streams.
func (e *Encryptor) EncryptFile(srcPath, destPath, password string) error {
	// Open source file
	srcFile, srcInfo, err := e.fileManager.OpenFile(srcPath)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close() //nolint:errcheck

	// Create destination file
	destFile, err := e.fileManager.CreateFile(destPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer destFile.Close() //nolint:errcheck

	// Generate salt for key derivation
	salt, err := keys.GetRandomSalt(config.SaltSize)
	if err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive key from password
	key, err := keys.Hash([]byte(password), salt)
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}

	// Validate file size
	originalSize := srcInfo.Size()
	if originalSize < 0 {
		return fmt.Errorf("invalid file size: %d", originalSize)
	}

	// Create and write header
	h, err := header.NewHeader(uint64(originalSize), salt, key)
	if err != nil {
		return fmt.Errorf("failed to create header: %w", err)
	}

	if err := h.Write(destFile); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Create stream processor for encryption
	config := streaming.StreamConfig{
		Key:         key,
		Processing:  options.Encryption,
		Concurrency: config.MaxConcurrency,
		ChunkSize:   config.DefaultChunkSize,
	}

	processor, err := streaming.NewStreamProcessor(config)
	if err != nil {
		return fmt.Errorf("failed to create stream processor: %w", err)
	}

	// Process the file
	if err := processor.Process(context.Background(), srcFile, destFile, originalSize); err != nil {
		return fmt.Errorf("failed to process file: %w", err)
	}

	return nil
}
