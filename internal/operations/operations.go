// Package operations provides file encryption and decryption functionalities.
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
	// Encrypt encrypts the source file and saves it to the destination file.
	Encrypt(srcPath, destPath, password string) error
	// Decrypt decrypts the source file and saves it to the destination file.
	Decrypt(srcPath, destPath, password string) error
}

// fileOperations implements the FileOperations interface.
type fileOperations struct {
	fileManager files.FileManager
}

// NewFileOperations creates a new FileOperations instance.
func NewFileOperations(fileManager files.FileManager) FileOperations {
	return &fileOperations{fileManager: fileManager}
}

// Encrypt encrypts the source file and saves it to the destination file.
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

	// Derive the encryption key from the password and salt.
	key, err := kdf.Hash([]byte(password), salt)
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}

	// Get the original file size.
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

	// Create a new stream processor and process the file.
	processor, err := streaming.NewStreamProcessor(key, options.Encryption)
	if err != nil {
		return fmt.Errorf("failed to create stream processor: %w", err)
	}

	if err := processor.Process(context.Background(), srcFile, destFile, originalSize); err != nil {
		return fmt.Errorf("failed to process file: %w", err)
	}

	return nil
}

// Decrypt decrypts the source file and saves it to the destination file.
func (o *fileOperations) Decrypt(srcPath, destPath, password string) error {
	// Open the source file.
	srcFile, _, err := o.fileManager.OpenFile(srcPath)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close() //nolint:errcheck

	// Read and verify the magic bytes.
	magic, err := header.ReadMagic(srcFile)
	if err != nil {
		return fmt.Errorf("failed to read magic bytes: %w", err)
	}

	if !header.VerifyMagic(magic) {
		return fmt.Errorf("invalid magic bytes: not a sweetbyte file")
	}

	// Read the salt.
	salt, err := header.ReadSalt(srcFile)
	if err != nil {
		return fmt.Errorf("failed to read salt: %w", err)
	}

	// Derive the decryption key from the password and salt.
	key, err := kdf.Hash([]byte(password), salt)
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}

	// Unmarshal the header.
	h, err := header.Unmarshal(srcFile, key, magic, salt)
	if err != nil {
		return fmt.Errorf("decryption failed: incorrect password or corrupt file: %w", err)
	}

	// Create the destination file.
	destFile, err := o.fileManager.CreateFile(destPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer destFile.Close() //nolint:errcheck

	// Create a new stream processor and process the file.
	processor, err := streaming.NewStreamProcessor(key, options.Decryption)
	if err != nil {
		return fmt.Errorf("failed to create stream processor: %w", err)
	}

	// #nosec G115
	if err := processor.Process(context.Background(), srcFile, destFile, int64(h.OriginalSize)); err != nil {
		return fmt.Errorf("failed to process file: %w", err)
	}

	return nil
}
