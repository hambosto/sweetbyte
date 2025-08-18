// Package files provides file system operations for the SweetByte application.
package files

import (
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

// Finder finds files that are eligible for encryption or decryption.
type Finder struct{}

// NewFinder creates a new Finder.
func NewFinder() *Finder {
	return &Finder{}
}

// FindEligibleFiles finds all files in the current directory that are eligible for the given processing mode.
func (f *Finder) FindEligibleFiles(mode options.ProcessorMode) ([]string, error) {
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
func (f *Finder) isFileEligible(path string, info os.FileInfo, mode options.ProcessorMode) bool {
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
func (f *Finder) isHiddenFile(filename string) bool {
	return strings.HasPrefix(filename, ".")
}

// shouldSkipPath checks if a path should be skipped based on the excluded directories and extensions.
func (f *Finder) shouldSkipPath(path string) bool {
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
func (f *Finder) IsEncryptedFile(path string) bool {
	return strings.HasSuffix(path, config.FileExtension)
}

// GetOutputPath returns the output path for a given input path and processing mode.
func (f *Finder) GetOutputPath(inputPath string, mode options.ProcessorMode) string {
	// If encrypting, add the file extension.
	if mode == options.ModeEncrypt {
		return inputPath + config.FileExtension
	}

	// If decrypting, remove the file extension.
	return strings.TrimSuffix(inputPath, config.FileExtension)
}

// GetFileInfo returns information about a list of files.
func (f *Finder) GetFileInfo(files []string) ([]FileInfo, error) {
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
