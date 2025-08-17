// Package files provides utilities for managing file system operations,
// including opening, creating, validating, and securely deleting files.
package files

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/options"
)

// FileInfo represents detailed information about a file, including its path, size,
// whether it's encrypted, and its eligibility for a given operation.
type FileInfo struct {
	Path        string // The absolute or relative path to the file.
	Size        int64  // The size of the file in bytes.
	IsEncrypted bool   // True if the file has the SweetByte encrypted file extension.
	IsEligible  bool   // True if the file is eligible for the current encryption/decryption operation.
}

// Finder provides methods for discovering and filtering files within the file system.
// It helps identify files that are eligible for encryption or decryption operations
// based on their naming conventions and other criteria.
type Finder struct{}

// NewFinder creates and returns a new Finder instance.
func NewFinder() *Finder {
	return &Finder{}
}

// FindEligibleFiles walks the current directory and its subdirectories
// to find files that are eligible for the specified processing mode (encryption or decryption).
// It skips directories, hidden files, and files/paths explicitly excluded in the configuration.
func (f *Finder) FindEligibleFiles(mode options.ProcessorMode) ([]string, error) {
	var files []string // Slice to store paths of eligible files.

	// Walk through the file system starting from the current directory.
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil { // If an error occurs during walking (e.g., permission denied).
			return err // Propagate the error.
		}
		// Check if the current file/directory is eligible based on its properties and the processing mode.
		if f.isFileEligible(path, info, mode) {
			files = append(files, path) // If eligible, add its path to the list.
		}
		return nil // Continue walking.
	})
	if err != nil {
		return nil, fmt.Errorf("failed to scan for eligible files: %w", err) // Return error if walking fails.
	}
	return files, nil // Return the list of eligible files.
}

// isFileEligible determines if a given file or directory is suitable for processing
// based on its type, name, exclusion lists, and the current processing mode.
func (f *Finder) isFileEligible(path string, info os.FileInfo, mode options.ProcessorMode) bool {
	// Skip directories, hidden files, and explicitly excluded paths/extensions.
	if info.IsDir() || f.isHiddenFile(info.Name()) || f.shouldSkipPath(path) {
		return false
	}

	// Determine if the file is already encrypted based on its extension.
	isEncrypted := strings.HasSuffix(path, config.FileExtension)
	// A file is eligible if it's for encryption and not already encrypted, OR
	// if it's for decryption and is already encrypted.
	return (mode == options.ModeEncrypt && !isEncrypted) || (mode == options.ModeDecrypt && isEncrypted)
}

// isHiddenFile checks if a filename represents a hidden file (starts with a dot).
func (f *Finder) isHiddenFile(filename string) bool {
	return strings.HasPrefix(filename, ".")
}

// shouldSkipPath checks if a given path or its extension is in the exclusion lists.
func (f *Finder) shouldSkipPath(path string) bool {
	// Check against excluded directories.
	for _, dir := range config.ExcludedDirs {
		if strings.Contains(path, dir) {
			return true
		}
	}

	// Check against excluded file extensions.
	for _, ext := range config.ExcludedExts {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}

	return false
}

// IsEncryptedFile checks if a file path indicates an encrypted SweetByte file
// by verifying its file extension.
func (f *Finder) IsEncryptedFile(path string) bool {
	return strings.HasSuffix(path, config.FileExtension)
}

// GetOutputPath generates the default output file path based on the input path and processing mode.
// For encryption, it appends the SweetByte extension. For decryption, it removes it.
func (f *Finder) GetOutputPath(inputPath string, mode options.ProcessorMode) string {
	if mode == options.ModeEncrypt { // If encrypting, append the default extension.
		return inputPath + config.FileExtension
	}
	// If decrypting, remove the default extension from the input path.
	return strings.TrimSuffix(inputPath, config.FileExtension)
}

// GetFileInfo retrieves detailed FileInfo for a list of file paths.
// It includes the file size, encryption status, and eligibility (which is assumed true here).
func (f *Finder) GetFileInfo(files []string) ([]FileInfo, error) {
	var fileInfos []FileInfo // Slice to store FileInfo structs.

	for _, file := range files { // Iterate over each file path.
		info, err := os.Stat(file) // Get basic file system information.
		if err != nil {
			return nil, fmt.Errorf("failed to get file info for '%s': %w", file, err) // Return error if stat fails.
		}

		fileInfo := FileInfo{ // Populate the FileInfo struct.
			Path:        file,
			Size:        info.Size(),
			IsEncrypted: f.IsEncryptedFile(file), // Check if the file is encrypted.
			IsEligible:  true,                    // Assume eligibility as it comes from FindEligibleFiles.
		}

		fileInfos = append(fileInfos, fileInfo) // Add the populated FileInfo to the slice.
	}

	return fileInfos, nil // Return the slice of FileInfo and nil error.
}
