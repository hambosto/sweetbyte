package files

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/types"
)

// Finder is responsible for finding files eligible for processing
type Finder struct{}

// NewFinder creates a new file finder instance
func NewFinder() *Finder {
	return &Finder{}
}

// FindEligibleFiles walks the current directory tree and returns a list of files
// eligible for encryption or decryption, based on the specified mode
func (f *Finder) FindEligibleFiles(mode types.ProcessorMode) ([]string, error) {
	var files []string

	// Walk through all files and directories starting from current directory
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if f.isFileEligible(path, info, mode) {
			files = append(files, path)
		}
		return nil
	})

	return files, err
}

// isFileEligible checks if a given file should be processed based on its extension,
// whether it's hidden, or excluded via config, and depending on the selected mode
func (f *Finder) isFileEligible(path string, info os.FileInfo, mode types.ProcessorMode) bool {
	// Skip directories, hidden files, or excluded paths
	if info.IsDir() || f.isHiddenFile(info.Name()) || f.shouldSkipPath(path) {
		return false
	}

	// Check file suffix to determine if it's encrypted
	isEncrypted := strings.HasSuffix(path, config.FileExtension)

	// Include unencrypted files in encrypt mode, and encrypted files in decrypt mode
	return (mode == types.ModeEncrypt && !isEncrypted) || (mode == types.ModeDecrypt && isEncrypted)
}

// isHiddenFile checks if a file is hidden (starts with dot)
func (f *Finder) isHiddenFile(filename string) bool {
	return strings.HasPrefix(filename, ".")
}

// shouldSkipPath returns true if the file should be excluded based on directory or extension rules
func (f *Finder) shouldSkipPath(path string) bool {
	// Check excluded directories
	for _, dir := range config.ExcludedDirs {
		if strings.Contains(path, dir) {
			return true
		}
	}

	// Check excluded extensions
	for _, ext := range config.ExcludedExts {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}

	return false
}

// IsEncryptedFile checks if a file is encrypted based on its extension
func (f *Finder) IsEncryptedFile(path string) bool {
	return strings.HasSuffix(path, config.FileExtension)
}

// GetOutputPath determines the output path based on the operation mode
func (f *Finder) GetOutputPath(inputPath string, mode types.ProcessorMode) string {
	if mode == types.ModeEncrypt {
		return inputPath + config.FileExtension
	}
	return strings.TrimSuffix(inputPath, config.FileExtension)
}

// GetFileInfo returns detailed information about files
func (f *Finder) GetFileInfo(files []string) ([]types.FileInfo, error) {
	var fileInfos []types.FileInfo

	for _, file := range files {
		info, err := os.Stat(file)
		if err != nil {
			continue // Skip files that can't be accessed
		}

		fileInfo := types.FileInfo{
			Path:        file,
			Size:        info.Size(),
			IsEncrypted: f.IsEncryptedFile(file),
			IsEligible:  true, // Already filtered by FindEligibleFiles
		}

		fileInfos = append(fileInfos, fileInfo)
	}

	return fileInfos, nil
}
