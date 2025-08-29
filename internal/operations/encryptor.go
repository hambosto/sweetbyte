// Package operations provides high-level encryption and decryption operations.
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

// Encryptor handles the encryption of files.
type Encryptor struct {
	fileManager *files.Manager
	fileFinder  *files.Finder
}

// NewEncryptor creates a new Encryptor.
func NewEncryptor() *Encryptor {
	return &Encryptor{
		fileManager: files.NewManager(),
		fileFinder:  files.NewFinder(),
	}
}

// EncryptFile encrypts a file.
func (e *Encryptor) EncryptFile(srcPath, destPath, password string) error {
	// Open the source file.
	srcFile, srcInfo, err := e.fileManager.OpenFile(srcPath)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close() //nolint:errcheck

	// Create the destination file.
	destFile, err := e.fileManager.CreateFile(destPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer destFile.Close() //nolint:errcheck

	// Generate a random salt.
	salt, err := keys.GetRandomSalt(config.SaltSize)
	if err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive the key from the password and salt.
	key, err := keys.Hash([]byte(password), salt)
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}

	// Get the original size of the file.
	originalSize := srcInfo.Size()
	if originalSize < 0 {
		return fmt.Errorf("invalid file size: %d", originalSize)
	}

	// Create a new header.
	h, err := header.New(uint64(originalSize))
	if err != nil {
		return fmt.Errorf("failed to create header: %w", err)
	}

	// Marshal the header and write it to the destination file.
	headerBytes, err := h.Marshal(salt, key)
	if err != nil {
		return fmt.Errorf("failed to marshal header: %w", err)
	}
	if _, err := destFile.Write(headerBytes); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Create a new stream processor for encryption.
	config := streaming.StreamConfig{
		Key:        key,
		Processing: options.Encryption,
		ChunkSize:  config.DefaultChunkSize,
	}

	processor, err := streaming.NewStreamProcessor(config)
	if err != nil {
		return fmt.Errorf("failed to create stream processor: %w", err)
	}

	// Process the file.
	if err := processor.Process(context.Background(), srcFile, destFile, originalSize); err != nil {
		return fmt.Errorf("failed to process file: %w", err)
	}

	return nil
}
