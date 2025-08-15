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

// Encryptor handles file encryption operations
type Encryptor struct {
	fileManager *files.Manager
	fileFinder  *files.Finder
}

// NewEncryptor creates a new encryptor instance
func NewEncryptor() *Encryptor {
	return &Encryptor{
		fileManager: files.NewManager(),
		fileFinder:  files.NewFinder(),
	}
}

// EncryptFile encrypts a file from source to destination
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
	h, err := header.New(salt, uint64(originalSize), key)
	if err != nil {
		return fmt.Errorf("failed to create header: %w", err)
	}

	if err := h.Write(destFile); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Create stream processor for encryption
	config := streaming.Config{
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
	return processor.Process(context.Background(), srcFile, destFile, originalSize)
}
