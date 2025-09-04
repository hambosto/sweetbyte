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

// fileDecryptor handles the decryption of files.
type fileDecryptor struct {
	fileManager files.FileManager
}

// NewDecryptor creates a new Decryptor.
func NewDecryptor(fileManager files.FileManager) Decryptor {
	return &fileDecryptor{
		fileManager: fileManager,
	}
}

// DecryptFile decrypts a file.
func (d *fileDecryptor) DecryptFile(srcPath, destPath, password string) error {
	// Open the source file.
	srcFile, _, err := d.fileManager.OpenFile(srcPath)
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
	key, err := keys.Hash([]byte(password), salt)
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
	destFile, err := d.fileManager.CreateFile(destPath)
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