// Package operations provides high-level encryption and decryption operations.
package operations

import (
	"context"
	"fmt"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/files"
	"github.com/hambosto/sweetbyte/internal/header"
	"github.com/hambosto/sweetbyte/internal/kdf"
	"github.com/hambosto/sweetbyte/internal/options"
	"github.com/hambosto/sweetbyte/internal/streaming"
)

// FileOperations defines the interface for file operations.
type FileOperations interface {
	Encrypt(srcPath, destPath, password string) error
	Decrypt(srcPath, destPath, password string) error
}

// fileDecryptor handles the encryption and decryption of files.
type fileOperations struct {
	fileManager files.FileManager
}

// NewFileOperations creates a new fileOperations.
func NewFileOperations(fileManager files.FileManager) FileOperations {
	return &fileOperations{fileManager: fileManager}
}

func (o *fileOperations) Encrypt(srcPath, destPath, password string) error {
	// Open the source file.
	srcFile, srcInfo, err := o.fileManager.OpenFile(srcPath)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close() //nolint:errcheck

	// Create the destination file.
	destFile, err := o.fileManager.CreateFile(destPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer destFile.Close() //nolint:errcheck

	// Generate a random salt.
	salt, err := kdf.GetRandomSalt(config.SaltSize)
	if err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive the key from the password and salt.
	key, err := kdf.Hash([]byte(password), salt)
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}

	// Get the original size of the file.
	originalSize := srcInfo.Size()
	if originalSize < 0 {
		return fmt.Errorf("invalid file size: %d", originalSize)
	}

	// Create a new header.
	h, err := header.NewHeader(uint64(originalSize))
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

func (o *fileOperations) Decrypt(srcPath, destPath, password string) error {
	// Open the source file.
	srcFile, _, err := o.fileManager.OpenFile(srcPath)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close() //nolint:errcheck

	magic, err := header.ReadMagic(srcFile)
	if err != nil {
		return fmt.Errorf("failed to read magic bytes: %w", err)
	}

	if !header.VerifyMagic(magic) {
		return fmt.Errorf("invalid magic bytes: not a sweetbyte file")
	}

	salt, err := header.ReadSalt(srcFile)
	if err != nil {
		return fmt.Errorf("failed to read salt: %w", err)
	}

	// Derive the key from the password and salt.
	key, err := kdf.Hash([]byte(password), salt)
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}

	// Unmarshal and verify the rest of the header.
	h, err := header.Unmarshal(srcFile, key, magic, salt)
	if err != nil {
		return fmt.Errorf("decryption failed: incorrect password or corrupt file: %w", err)
	}

	// Get the original size of the file from the header.
	// #nosec G115
	originalSize := int64(h.OriginalSize)

	// Create the destination file.
	destFile, err := o.fileManager.CreateFile(destPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer destFile.Close() //nolint:errcheck

	// Create a new stream processor for decryption.
	config := streaming.StreamConfig{
		Key:        key,
		Processing: options.Decryption,
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
