// Package files provides utilities for managing file system operations,
// including opening, creating, validating, and securely deleting files.
package files

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/options"
)

// Manager provides methods for interacting with the file system.
// It encapsulates operations like file removal (including secure deletion),
// creation, path validation, and basic file information retrieval.
type Manager struct{}

// NewManager creates and returns a new file Manager instance.
// It is an empty struct as its methods operate directly on file paths and options.
func NewManager() *Manager {
	return &Manager{}
}

// Remove deletes a file from the specified path based on the given deletion option.
// It supports standard deletion (os.Remove) and secure deletion (overwriting before deleting).
func (m *Manager) Remove(path string, option options.DeleteOption) error {
	switch option { // Determine deletion method based on the option.
	case options.DeleteStandard: // Standard file deletion.
		if err := os.Remove(path); err != nil { // Use os.Remove to delete the file.
			return fmt.Errorf("failed to remove file %s: %w", path, err) // Return error if removal fails.
		}
		return nil
	case options.DeleteSecure: // Secure file deletion.
		return m.secureDelete(path) // Call the secure deletion method.
	default:
		return fmt.Errorf("unsupported delete option %s", option) // Return error for unknown delete options.
	}
}

// CreateFile creates a new file at the specified path.
// It ensures the path is cleaned for security and consistency.
func (m *Manager) CreateFile(path string) (*os.File, error) {
	output, err := os.Create(filepath.Clean(path)) // Create the file, cleaning the path first.
	if err != nil {
		return nil, fmt.Errorf("failed to create file %s: %w", path, err) // Return error if file creation fails.
	}
	return output, nil // Return the created file handle.
}

// ValidatePath checks the existence and accessibility of a file path.
// If `mustExist` is true, it verifies the file exists and is not empty.
// If `mustExist` is false, it verifies the file does NOT exist (for output paths).
func (m *Manager) ValidatePath(path string, mustExist bool) error {
	fileInfo, err := os.Stat(path) // Get file information.

	if mustExist { // Validation for an input file that must exist.
		if os.IsNotExist(err) { // Check if the file does not exist.
			return fmt.Errorf("file not found: %s", path) // Return error if file not found.
		}
		if err != nil { // Handle other errors during file access (e.g., permissions).
			return fmt.Errorf("failed to access file %s: %w", path, err)
		}
		if fileInfo.Size() == 0 { // Check if the file is empty.
			return fmt.Errorf("file is empty and cannot be processed: %s", path) // Return error for empty file.
		}
	} else { // Validation for an output file that must NOT exist (to prevent overwrites).
		if err == nil { // If err is nil, the file exists.
			return fmt.Errorf("output file already exists: %s", path) // Return error if output file already exists.
		}
		if !os.IsNotExist(err) { // Handle other errors when checking for output file existence.
			return fmt.Errorf("error accessing file %s: %w", path, err)
		}
	}
	return nil // Return nil if validation passes.
}

// OpenFile opens a file for reading and returns its file handle and information.
// It cleans the provided path for security.
func (m *Manager) OpenFile(path string) (*os.File, os.FileInfo, error) {
	file, err := os.Open(filepath.Clean(path)) // Open the file, cleaning the path.
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open file %s: %w", path, err) // Return error if file opening fails.
	}

	info, err := file.Stat() // Get file information (size, mode, etc.).
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get file info for %s: %w", path, err) // Return error if getting info fails.
	}
	return file, info, nil // Return the file handle, info, and nil error.
}

// GetFileInfo retrieves and returns the os.FileInfo for a given path.
func (m *Manager) GetFileInfo(path string) (os.FileInfo, error) {
	info, err := os.Stat(filepath.Clean(path)) // Get file info, cleaning path first.
	if err != nil {
		if os.IsNotExist(err) { // Check if file does not exist.
			return nil, fmt.Errorf("file not found: %s", path) // Return error for file not found.
		}
		return nil, fmt.Errorf("failed to get file info for %s: %w", path, err) // Handle other access errors.
	}
	return info, nil // Return file info and nil error.
}

// FileExists checks if a file exists at the specified path.
func (m *Manager) FileExists(path string) bool {
	_, err := os.Stat(filepath.Clean(path)) // Attempt to get file info; error indicates non-existence or permission issues.
	return err == nil                       // Return true if no error (file exists and is accessible).
}

// secureDelete performs a secure deletion of a file by overwriting its content
// with random data multiple times before finally removing it. This makes data recovery very difficult.
func (m *Manager) secureDelete(path string) error {
	// Open the file for writing to overwrite its content.
	file, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open file %s for secure deletion: %w", path, err)
	}

	// Get file information to determine its size for overwriting.
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to get file info for secure deletion %s: %w", path, err)
	}

	// Perform multiple passes of random data overwrite.
	for pass := range config.OverwritePasses { // Iterate through the configured number of overwrite passes.
		if err := m.randomOverwrite(file, info.Size()); err != nil {
			return fmt.Errorf("secure overwrite pass %d failed for %s: %w", pass+1, path, err)
		}
	}

	// Close the file after overwriting.
	if err := file.Close(); err != nil {
		return fmt.Errorf("failed to close file %s before removal: %w", path, err)
	}

	// Finally, remove the file from the file system.
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("failed to remove file %s after secure overwrite: %w", path, err)
	}

	return nil // Return nil on successful secure deletion.
}

// randomOverwrite fills the entire content of an open file with cryptographically random data.
// It seeks to the beginning of the file and writes random bytes in chunks.
func (m *Manager) randomOverwrite(file *os.File, size int64) error {
	if _, err := file.Seek(0, 0); err != nil { // Seek to the beginning of the file.
		return fmt.Errorf("failed to seek to file start: %w", err) // Handle seek error.
	}

	buffer := make([]byte, 4096) // Create a buffer for writing random data in chunks.
	remaining := size            // Initialize remaining bytes to write with file size.

	for remaining > 0 { // Loop until all bytes are overwritten.
		writeSize := min(remaining, int64(len(buffer))) // Determine the size of the current write operation.

		if _, err := rand.Read(buffer[:writeSize]); err != nil { // Fill the buffer with random data.
			return fmt.Errorf("failed to generate random data: %w", err) // Handle random data generation error.
		}

		if _, err := file.Write(buffer[:writeSize]); err != nil { // Write the random data to the file.
			return fmt.Errorf("failed to write random data: %w", err) // Handle write error.
		}

		remaining -= writeSize // Decrease remaining bytes.
	}

	if err := file.Sync(); err != nil { // Ensure all buffered data is written to disk.
		return fmt.Errorf("failed to sync file to storage: %w", err) // Handle sync error.
	}
	return nil // Return nil on successful overwrite.
}
