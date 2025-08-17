package operations

import (
	"context"
	"fmt"

	// Import the 'os' package to work with file information.
	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/files"
	"github.com/hambosto/sweetbyte/internal/header"
	"github.com/hambosto/sweetbyte/internal/keys"
	"github.com/hambosto/sweetbyte/internal/options"
	"github.com/hambosto/sweetbyte/internal/streaming"
)

// Encryptor handles the end-to-end encryption of a single file.
// It orchestrates various components like file management, key derivation,
// header creation, and the streaming encryption process.
type Encryptor struct {
	fileManager *files.Manager
	fileFinder  *files.Finder
}

// NewEncryptor creates and returns a new Encryptor instance.
// It initializes the necessary file management utilities.
func NewEncryptor() *Encryptor {
	return &Encryptor{
		fileManager: files.NewManager(), // Initialize the file manager for file operations.
		fileFinder:  files.NewFinder(),  // Initialize the file finder for locating files.
	}
}

// EncryptFile encrypts a file from srcPath to destPath using the provided password.
// This method encapsulates the entire encryption workflow, including:
//   - Opening source and creating destination files.
//   - Generating a random salt and deriving an encryption key from the password.
//   - Creating and writing a secure header to the destination file.
//   - Setting up and executing the streaming encryption process.
func (e *Encryptor) EncryptFile(srcPath, destPath, password string) error {
	// Open the source file and get its information.
	srcFile, srcInfo, err := e.fileManager.OpenFile(srcPath)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close() // Ensure the source file is closed after the function exits.

	// Create the destination file where the encrypted data will be written.
	destFile, err := e.fileManager.CreateFile(destPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer destFile.Close() // Ensure the destination file is closed.

	// Generate a cryptographically secure random salt.
	salt, err := keys.GetRandomSalt(config.SaltSize)
	if err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	// Derive a strong encryption key from the user's password and the generated salt.
	key, err := keys.Hash([]byte(password), salt)
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}

	// Get the original size of the source file.
	originalSize := srcInfo.Size()
	if originalSize < 0 {
		return fmt.Errorf("invalid file size: %d", originalSize)
	}

	// Create a new header object with the original file size, salt, and encryption key.
	h, err := header.NewHeader(uint64(originalSize), salt, key)
	if err != nil {
		return fmt.Errorf("failed to create header: %w", err)
	}

	// Write the header to the beginning of the destination file.
	if err := h.Write(destFile); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	// Initialize streaming configuration with the derived key, encryption mode,
	// and predefined concurrency/chunk size settings.
	config := streaming.StreamConfig{
		Key:         key,                     // The encryption key derived from the password.
		Processing:  options.Encryption,      // Set the processing mode to encryption.
		Concurrency: config.MaxConcurrency,   // Max number of concurrent goroutines for processing.
		ChunkSize:   config.DefaultChunkSize, // Default size of data chunks to process.
	}

	// Create a new stream processor with the defined configuration.
	processor, err := streaming.NewStreamProcessor(config)
	if err != nil {
		return fmt.Errorf("failed to create stream processor: %w", err) // Propagate error if stream processor creation fails.
	}

	// Process the file using the stream processor, handling data transfer and encryption.
	// This streams the data from the source file, encrypts it, and writes it to the destination file.
	if err := processor.Process(context.Background(), srcFile, destFile, originalSize); err != nil {
		return fmt.Errorf("failed to process file: %w", err) // Propagate error if file processing fails.
	}

	return nil // Return nil on successful encryption.
}
