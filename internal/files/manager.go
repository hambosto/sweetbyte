package files

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/options"
)

type Manager struct{}

func NewManager() *Manager {
	return &Manager{}
}

func (m *Manager) Remove(path string, option options.DeleteOption) error {
	switch option {
	case options.DeleteStandard:
		if err := os.Remove(path); err != nil {
			return fmt.Errorf("failed to remove file %s: %w", path, err)
		}
		return nil
	case options.DeleteSecure:
		return m.secureDelete(path)
	default:
		return fmt.Errorf("unsupported delete option %s", option)
	}
}

func (m *Manager) CreateFile(path string) (*os.File, error) {
	output, err := os.Create(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("failed to create file %s: %w", path, err)
	}
	return output, nil
}

func (m *Manager) ValidatePath(path string, mustExist bool) error {
	fileInfo, err := os.Stat(path)

	if mustExist {
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
		if err == nil {
			return fmt.Errorf("output file already exists: %s", path)
		}
		if !os.IsNotExist(err) {
			return fmt.Errorf("error accessing file %s: %w", path, err)
		}
	}

	return nil
}

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

func (m *Manager) secureDelete(path string) error {
	file, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open file %s for secure deletion: %w", path, err)
	}

	info, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to get file info for secure deletion %s: %w", path, err)
	}

	for pass := range config.OverwritePasses {
		if err := m.randomOverwrite(file, info.Size()); err != nil {
			return fmt.Errorf("secure overwrite pass %d failed for %s: %w", pass+1, path, err)
		}
	}

	if err := file.Close(); err != nil {
		return fmt.Errorf("failed to close file %s before removal: %w", path, err)
	}

	if err := os.Remove(path); err != nil {
		return fmt.Errorf("failed to remove file %s after secure overwrite: %w", path, err)
	}

	return nil
}

func (m *Manager) randomOverwrite(file *os.File, size int64) error {
	if _, err := file.Seek(0, 0); err != nil {
		return fmt.Errorf("failed to seek to file start: %w", err)
	}

	buffer := make([]byte, 4096)
	remaining := size
	for remaining > 0 {
		writeSize := min(remaining, int64(len(buffer)))

		if _, err := rand.Read(buffer[:writeSize]); err != nil {
			return fmt.Errorf("failed to generate random data: %w", err)
		}

		if _, err := file.Write(buffer[:writeSize]); err != nil {
			return fmt.Errorf("failed to write random data: %w", err)
		}

		remaining -= writeSize
	}

	if err := file.Sync(); err != nil {
		return fmt.Errorf("failed to sync file to storage: %w", err)
	}
	return nil
}
