// Package files provides file system operations for the SweetByte application.
package files

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/options"
)

// Manager handles file operations such as creating, opening, and deleting files.
type Manager struct{}

// NewManager creates a new Manager.
func NewManager() *Manager {
	return &Manager{}
}

// Remove removes a file with the specified delete option.
func (m *Manager) Remove(path string, option options.DeleteOption) error {
	switch option {
	case options.DeleteStandard:
		// Standard file removal.
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("failed to remove file %s: %w", path, err)
		}
		return nil
	case options.DeleteSecure:
		// Secure file deletion.
		return m.secureDelete(path)
	default:
		return fmt.Errorf("unsupported delete option %s", option)
	}
}

// CreateFile creates a new file at the specified path.
func (m *Manager) CreateFile(path string) (*os.File, error) {
	output, err := os.Create(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("failed to create file %s: %w", path, err)
	}
	return output, nil
}

// ValidatePath validates a file path.
func (m *Manager) ValidatePath(path string, mustExist bool) error {
	fileInfo, err := os.Stat(path)

	if mustExist {
		// If the file must exist, check for errors.
		if os.IsNotExist(err) {
			return fmt.Errorf("file not found: %s", path)
		}
		if err != nil {
			return fmt.Errorf("failed to access file %s: %w", path, err)
		}
		if fileInfo.Size() == 0 {
			return fmt.Errorf("file is empty and cannot be processed: %s", path)
		}
	} else {
		// If the file must not exist, check for errors.
		if err == nil {
			return fmt.Errorf("output file already exists: %s", path)
		}
		if !os.IsNotExist(err) {
			return fmt.Errorf("error accessing file %s: %w", path, err)
		}
	}

	return nil
}

// OpenFile opens a file at the specified path.
func (m *Manager) OpenFile(path string) (*os.File, os.FileInfo, error) {
	file, err := os.Open(filepath.Clean(path))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open file %s: %w", path, err)
	}

	info, err := file.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get file info for %s: %w", path, err)
	}
	return file, info, nil
}

// GetFileInfo gets information about a file at the specified path.
func (m *Manager) GetFileInfo(path string) (os.FileInfo, error) {
	info, err := os.Stat(filepath.Clean(path))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("file not found: %s", path)
		}
		return nil, fmt.Errorf("failed to get file info for %s: %w", path, err)
	}
	return info, nil
}

// secureDelete securely deletes a file by overwriting it with random data.
func (m *Manager) secureDelete(path string) error {
	// Open the file for writing.
	file, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open file %s for secure deletion: %w", path, err)
	}

	// Get the file info.
	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to get file info for secure deletion %s: %w", path, err)
	}

	// Overwrite the file with random data multiple times.
	for pass := range config.OverwritePasses {
		if err := m.randomOverwrite(file, info.Size()); err != nil {
			return fmt.Errorf("secure overwrite pass %d failed for %s: %w", pass+1, path, err)
		}
	}

	// Close the file.
	if err := file.Close(); err != nil {
		return fmt.Errorf("failed to close file %s before removal: %w", path, err)
	}

	// Remove the file.
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("failed to remove file %s after secure overwrite: %w", path, err)
	}

	return nil
}

// randomOverwrite overwrites a file with random data.
func (m *Manager) randomOverwrite(file *os.File, size int64) error {
	// Seek to the beginning of the file.
	if _, err := file.Seek(0, 0); err != nil {
		return fmt.Errorf("failed to seek to file start: %w", err)
	}

	// Create a buffer for writing random data.
	buffer := make([]byte, 4096)
	remaining := size
	for remaining > 0 {
		writeSize := min(remaining, int64(len(buffer)))

		// Generate random data.
		if _, err := rand.Read(buffer[:writeSize]); err != nil {
			return fmt.Errorf("failed to generate random data: %w", err)
		}

		// Write the random data to the file.
		if _, err := file.Write(buffer[:writeSize]); err != nil {
			return fmt.Errorf("failed to write random data: %w", err)
		}

		remaining -= writeSize
	}

	// Sync the file to ensure the data is written to disk.
	if err := file.Sync(); err != nil {
		return fmt.Errorf("failed to sync file to storage: %w", err)
	}
	return nil
}
