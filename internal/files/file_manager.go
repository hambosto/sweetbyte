// Package files provides file system operations for the SweetByte application.
package files

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/options"
)

// FileInfo represents information about a file.
type FileInfo struct {
	Path        string
	Size        int64
	IsEncrypted bool
	IsEligible  bool
}

// FileManager defines the interface for file operations.
type FileManager interface {
	FindEligibleFiles(mode options.ProcessorMode) ([]string, error)
	IsEncryptedFile(path string) bool
	GetOutputPath(inputPath string, mode options.ProcessorMode) string
	GetFileInfoList(files []string) ([]FileInfo, error)
	Remove(path string, option options.DeleteOption) error
	CreateFile(path string) (*os.File, error)
	OpenFile(path string) (*os.File, os.FileInfo, error)
	GetFileInfo(path string) (os.FileInfo, error)
	ValidatePath(path string, mustExist bool) error
}

// fileManager handles file operations such as creating, opening, deleting files,
// and finding eligible files for encryption/decryption.
type fileManager struct {
	OverwritePasses int
}

// NewFileManager creates a new FileManager instance.
func NewFileManager(overwritePasses int) FileManager {
	return &fileManager{OverwritePasses: overwritePasses}
}

// FindEligibleFiles finds all files in the current directory that are eligible for the given processing mode.
func (f *fileManager) FindEligibleFiles(mode options.ProcessorMode) ([]string, error) {
	var files []string

	// Walk the current directory and find eligible files.
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if f.isFileEligible(path, info, mode) {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to scan for eligible files: %w", err)
	}

	return files, nil
}

// isFileEligible checks if a file is eligible for the given processing mode.
func (f *fileManager) isFileEligible(path string, info os.FileInfo, mode options.ProcessorMode) bool {
	// Skip directories, hidden files, and excluded paths.
	if info.IsDir() || f.isHiddenFile(info.Name()) || f.shouldSkipPath(path) {
		return false
	}
	// Check if the file is encrypted.
	isEncrypted := strings.HasSuffix(path, config.FileExtension)
	// Determine eligibility based on the processing mode.
	return (mode == options.ModeEncrypt && !isEncrypted) || (mode == options.ModeDecrypt && isEncrypted)
}

// isHiddenFile checks if a file is a hidden file.
func (f *fileManager) isHiddenFile(filename string) bool {
	return strings.HasPrefix(filename, ".")
}

// shouldSkipPath checks if a path should be skipped based on the excluded directories and extensions.
func (f *fileManager) shouldSkipPath(path string) bool {
	// Check for excluded directories.
	for _, dir := range config.ExcludedDirs {
		if strings.Contains(path, dir) {
			return true
		}
	}
	// Check for excluded extensions.
	for _, ext := range config.ExcludedExts {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}

	return false
}

// IsEncryptedFile checks if a file is an encrypted file.
func (f *fileManager) IsEncryptedFile(path string) bool {
	return strings.HasSuffix(path, config.FileExtension)
}

// GetOutputPath returns the output path for a given input path and processing mode.
func (f *fileManager) GetOutputPath(inputPath string, mode options.ProcessorMode) string {
	// If encrypting, add the file extension.
	if mode == options.ModeEncrypt {
		return inputPath + config.FileExtension
	}

	// If decrypting, remove the file extension.
	return strings.TrimSuffix(inputPath, config.FileExtension)
}

// GetFileInfoList returns information about a list of files.
func (f *fileManager) GetFileInfoList(files []string) ([]FileInfo, error) {
	var fileInfos []FileInfo

	// Get information for each file.
	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			return nil, fmt.Errorf("failed to get file info for '%s': %w", file, err)
		}

		fileInfo := FileInfo{
			Path:        file,
			Size:        info.Size(),
			IsEncrypted: f.IsEncryptedFile(file),
			IsEligible:  true,
		}

		fileInfos = append(fileInfos, fileInfo)
	}

	return fileInfos, nil
}

// Remove removes a file with the specified delete option.
func (f *fileManager) Remove(path string, option options.DeleteOption) error {
	cleanPath := filepath.Clean(path)

	if err := f.validateFileExists(cleanPath); err != nil {
		return fmt.Errorf("cannot remove file: %w", err)
	}

	switch option {
	case options.DeleteStandard:
		return f.standardDelete(cleanPath)
	case options.DeleteSecure:
		return f.secureDelete(cleanPath)
	default:
		return fmt.Errorf("unsupported delete option: %s", option)
	}
}

// CreateFile creates a new file at the specified path.
func (f *fileManager) CreateFile(path string) (*os.File, error) {
	cleanPath := filepath.Clean(path)

	// Ensure parent directory exists
	if err := f.ensureParentDir(cleanPath); err != nil {
		return nil, fmt.Errorf("failed to create parent directory: %w", err)
	}

	file, err := os.Create(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("failed to create file %s: %w", cleanPath, err)
	}

	return file, nil
}

// OpenFile opens a file at the specified path and returns file handle and os.FileInfo.
func (f *fileManager) OpenFile(path string) (*os.File, os.FileInfo, error) {
	cleanPath := filepath.Clean(path)

	file, err := os.Open(cleanPath)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to open file %s: %w", cleanPath, err)
	}

	info, err := file.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to stat file %s: %w", cleanPath, err)
	}

	return file, info, nil
}

// GetFileInfo retrieves os.FileInfo for a path.
func (f *fileManager) GetFileInfo(path string) (os.FileInfo, error) {
	cleanPath := filepath.Clean(path)
	stat, err := os.Stat(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to get file info for %s: %w", cleanPath, err)
	}
	return stat, nil
}

// ValidatePath validates a file path based on existence requirements.
func (f *fileManager) ValidatePath(path string, mustExist bool) error {
	info, err := f.GetFileInfo(path)
	if err != nil {
		return err
	}

	if mustExist {
		if info == nil {
			return fmt.Errorf("file not found: %s", path)
		}
		if info.IsDir() {
			return fmt.Errorf("path is a directory, not a file: %s", path)
		}
		if info.Size() == 0 {
			return fmt.Errorf("file is empty and cannot be processed: %s", path)
		}
	} else {
		if info != nil {
			return fmt.Errorf("output file already exists: %s", path)
		}
	}

	return nil
}

// standardDelete performs standard file deletion.
func (f *fileManager) standardDelete(path string) error {
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("failed to remove file %s: %w", path, err)
	}
	return nil
}

// secureDelete securely deletes a file by overwriting it with random data.
func (f *fileManager) secureDelete(path string) error {
	file, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("failed to open file %s for secure deletion: %w", path, err)
	}
	defer file.Close() //nolint:errcheck

	stat, err := file.Stat()
	if err != nil {
		return fmt.Errorf("failed to get file info for secure deletion %s: %w", path, err)
	}

	// Perform multiple overwrite passes
	for pass := 0; pass < f.OverwritePasses; pass++ {
		if err := f.overwriteWithRandomData(file, stat.Size()); err != nil {
			return fmt.Errorf("secure overwrite pass %d failed for %s: %w", pass+1, path, err)
		}
	}

	// Close before removal
	if err := file.Close(); err != nil {
		return fmt.Errorf("failed to close file %s before removal: %w", path, err)
	}

	// Finally remove the file
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("failed to remove file %s after secure overwrite: %w", path, err)
	}

	return nil
}

// overwriteWithRandomData overwrites a file with random data.
func (f *fileManager) overwriteWithRandomData(file *os.File, size int64) error {
	// Seek to the beginning of the file
	if _, err := file.Seek(0, 0); err != nil {
		return fmt.Errorf("failed to seek to file start: %w", err)
	}

	buffer := make([]byte, 4096)
	remaining := size

	for remaining > 0 {
		writeSize := min(remaining, int64(len(buffer)))

		// Generate random data
		if _, err := rand.Read(buffer[:writeSize]); err != nil {
			return fmt.Errorf("failed to generate random data: %w", err)
		}

		// Write random data to file
		if _, err := file.Write(buffer[:writeSize]); err != nil {
			return fmt.Errorf("failed to write random data: %w", err)
		}

		remaining -= writeSize
	}

	// Sync data to storage if configured
	if err := file.Sync(); err != nil {
		return fmt.Errorf("failed to sync file to storage: %w", err)
	}

	return nil
}

// validateFileExists checks if a file exists and is accessible.
func (f *fileManager) validateFileExists(path string) error {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("file not found: %s", path)
		}
		return fmt.Errorf("cannot access file %s: %w", path, err)
	}
	return nil
}

// ensureParentDir creates parent directories if they don't exist.
func (f *fileManager) ensureParentDir(path string) error {
	dir := filepath.Dir(path)
	if dir != "." && dir != "/" {
		return os.MkdirAll(dir, 0o750)
	}
	return nil
}
