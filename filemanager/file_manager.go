package filemanager

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hambosto/sweetbyte/config"
	"github.com/hambosto/sweetbyte/types"
)

const (
	OverwritePasses = 3
	PasswordMinLen  = 8
)

type FileManager struct {
	overwritePasses int
}

func NewFileManager(passes int) *FileManager {
	return &FileManager{overwritePasses: passes}
}

func (fm *FileManager) FindEligibleFiles(mode types.ProcessorMode) ([]string, error) {
	var files []string

	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if fm.isEligible(path, info, mode) {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to scan for eligible files: %w", err)
	}
	return files, nil
}

func (fm *FileManager) isEligible(path string, info os.FileInfo, mode types.ProcessorMode) bool {
	if info.IsDir() || strings.HasPrefix(info.Name(), ".") || fm.isExcluded(path) {
		return false
	}

	isEncrypted := fm.IsEncryptedFile(path)
	switch mode {
	case types.ModeEncrypt:
		return !isEncrypted
	case types.ModeDecrypt:
		return isEncrypted
	default:
		return false
	}
}

func (fm *FileManager) isExcluded(path string) bool {
	cleanPath := filepath.Clean(path)

	for _, dir := range config.ExcludedDirs {
		if strings.HasPrefix(cleanPath, dir) {
			return true
		}
	}

	for _, ext := range config.ExcludedExts {
		if strings.HasSuffix(cleanPath, ext) {
			return true
		}
	}
	return false
}

func (fm *FileManager) IsEncryptedFile(path string) bool {
	return strings.HasSuffix(path, config.FileExtension)
}

func (fm *FileManager) GetOutputPath(inputPath string, mode types.ProcessorMode) string {
	switch mode {
	case types.ModeEncrypt:
		return inputPath + config.FileExtension
	case types.ModeDecrypt:
		return strings.TrimSuffix(inputPath, config.FileExtension)
	default:
		return inputPath
	}
}

func (fm *FileManager) GetFileInfoList(files []string) ([][]any, error) {
	var infos [][]any
	for _, filePath := range files {
		stat, err := fm.GetFileInfo(filePath)
		if err != nil {
			return nil, fmt.Errorf("stat failed for %q: %w", filePath, err)
		}
		if stat == nil {
			return nil, fmt.Errorf("file not found: %s", filePath)
		}

		info := []any{
			filePath,
			stat.Size(),
			fm.IsEncryptedFile(filePath),
			true,
		}
		infos = append(infos, info)
	}
	return infos, nil
}

func (fm *FileManager) Remove(path string) error {
	cleanPath := fm.cleanPath(path)

	if err := fm.requireExists(cleanPath); err != nil {
		return fmt.Errorf("cannot remove: %w", err)
	}

	return os.Remove(cleanPath)
}

func (fm *FileManager) CreateFile(path string) (*os.File, error) {
	cleanPath := fm.cleanPath(path)

	if err := fm.ensureParentDir(cleanPath); err != nil {
		return nil, err
	}
	return os.Create(cleanPath)
}

func (fm *FileManager) OpenFile(path string) (*os.File, os.FileInfo, error) {
	cleanPath := fm.cleanPath(path)

	f, err := os.Open(cleanPath)
	if err != nil {
		return nil, nil, fmt.Errorf("open failed: %w", err)
	}

	info, err := f.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("stat failed: %w", err)
	}
	return f, info, nil
}

func (fm *FileManager) GetFileInfo(path string) (os.FileInfo, error) {
	cleanPath := fm.cleanPath(path)
	stat, err := os.Stat(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("stat failed: %w", err)
	}
	return stat, nil
}

func (fm *FileManager) ValidatePath(path string, mustExist bool) error {
	cleanPath := fm.cleanPath(path)

	info, err := fm.GetFileInfo(cleanPath)
	if err != nil {
		return err
	}

	if mustExist {
		switch {
		case info == nil:
			return fmt.Errorf("file not found: %s", cleanPath)
		case info.IsDir():
			return fmt.Errorf("path is directory: %s", cleanPath)
		case info.Size() == 0:
			return fmt.Errorf("file is empty: %s", cleanPath)
		}
	} else if info != nil {
		return fmt.Errorf("output exists: %s", cleanPath)
	}
	return nil
}

func (fm *FileManager) requireExists(path string) error {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("not found: %s", path)
		}
		return fmt.Errorf("access failed: %w", err)
	}
	return nil
}

func (fm *FileManager) ensureParentDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "." || dir == "/" {
		return nil
	}
	return os.MkdirAll(dir, 0o750)
}

func (fm *FileManager) cleanPath(path string) string {
	return filepath.Clean(path)
}
