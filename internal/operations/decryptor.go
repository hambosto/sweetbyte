// Package operations provides the core logic for encrypting and decrypting files.
// This includes managing file I/O, key derivation, header creation, and orchestrating
// the streaming data processing pipeline.
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

// Decryptor handles the end-to-end decryption of a single file.
// It orchestrates various components like file management, header reading and verification,
// key derivation, and the streaming data decryption process.
type Decryptor struct {
	fileManager *files.Manager
	fileFinder  *files.Finder
}

// NewDecryptor creates and returns a new Decryptor instance.
// It initializes the necessary file management utilities.
func NewDecryptor() *Decryptor {
	return &Decryptor{
		fileManager: files.NewManager(), // Initialize the file manager for file operations.
		fileFinder:  files.NewFinder(),  // Initialize the file finder for locating files.
	}
}

// DecryptFile decrypts an encrypted file from srcPath to destPath using the provided password.
// This method encapsulates the entire decryption workflow, including:
//   - Opening the source encrypted file.
//   - Reading and verifying the secure header.
//   - Deriving the encryption key from the password and header salt.
//   - Creating the destination file.
//   - Setting up and executing the streaming decryption process.
func (d *Decryptor) DecryptFile(srcPath, destPath, password string) error {
	srcFile, _, err := d.fileManager.OpenFile(srcPath) // Open the source encrypted file.
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err) // Propagate error if file opening fails.
	}
	defer srcFile.Close() // Ensure the source file is closed when the function exits.

	header, err := header.Read(srcFile) // Read the secure header from the encrypted file.
	if err != nil {
		return fmt.Errorf("failed to read header: %w", err) // Propagate error if header reading fails.
	}

	key, err := keys.Hash([]byte(password), header.Salt()) // Derive the key using the provided password and the salt from the header.
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err) // Propagate error if key derivation fails.
	}

	if err := header.Verify(key); err != nil { // Verify the header's integrity and authenticity using the derived key.
		return fmt.Errorf("decryption failed: incorrect password or corrupt file: %w", err) // Return specific error for decryption failure.
	}

	originalSize := header.OriginalSize() // Get the original size of the file from the header.
	if originalSize > math.MaxInt64 {     // Check for excessively large file sizes.
		return fmt.Errorf("file too large: %d bytes", originalSize) // Return error if file size exceeds maximum allowed.
	}

	destFile, err := d.fileManager.CreateFile(destPath) // Create the destination file for the decrypted content.
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err) // Propagate error if destination file creation fails.
	}
	defer destFile.Close() // Ensure the destination file is closed when the function exits.

	config := streaming.StreamConfig{ // Configure the streaming processor for decryption.
		Key:         key,                     // The derived decryption key.
		Processing:  options.Decryption,      // Set processing mode to decryption.
		Concurrency: config.MaxConcurrency,   // Max concurrent operations.
		ChunkSize:   config.DefaultChunkSize, // Default chunk size for processing.
	}

	processor, err := streaming.NewStreamProcessor(config) // Create a new stream processor.
	if err != nil {
		return fmt.Errorf("failed to create stream processor: %w", err) // Propagate error if stream processor creation fails.
	}

	if err := processor.Process(context.Background(), srcFile, destFile, int64(originalSize)); err != nil { // Start the decryption process.
		return fmt.Errorf("failed to process file: %w", err) // Propagate error if file processing fails.
	}

	return nil // Return nil on successful decryption.
}
