package files

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/options"
)

type FileInfo struct {
	Path        string
	Size        int64
	IsEncrypted bool
	IsEligible  bool
}

type Finder struct{}

func NewFinder() *Finder {
	return &Finder{}
}

func (f *Finder) FindEligibleFiles(mode options.ProcessorMode) ([]string, error) {
	var files []string

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

func (f *Finder) isFileEligible(path string, info os.FileInfo, mode options.ProcessorMode) bool {
	if info.IsDir() || f.isHiddenFile(info.Name()) || f.shouldSkipPath(path) {
		return false
	}
	isEncrypted := strings.HasSuffix(path, config.FileExtension)
	return (mode == options.ModeEncrypt && !isEncrypted) || (mode == options.ModeDecrypt && isEncrypted)
}

func (f *Finder) isHiddenFile(filename string) bool {
	return strings.HasPrefix(filename, ".")
}

func (f *Finder) shouldSkipPath(path string) bool {
	for _, dir := range config.ExcludedDirs {
		if strings.Contains(path, dir) {
			return true
		}
	}
	for _, ext := range config.ExcludedExts {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}

	return false
}

func (f *Finder) IsEncryptedFile(path string) bool {
	return strings.HasSuffix(path, config.FileExtension)
}

func (f *Finder) GetOutputPath(inputPath string, mode options.ProcessorMode) string {
	if mode == options.ModeEncrypt {
		return inputPath + config.FileExtension
	}

	return strings.TrimSuffix(inputPath, config.FileExtension)
}

func (f *Finder) GetFileInfo(files []string) ([]FileInfo, error) {
	var fileInfos []FileInfo

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
