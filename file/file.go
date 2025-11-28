package file

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hambosto/sweetbyte/config"
	"github.com/hambosto/sweetbyte/types"
)

type FileInfo struct {
	Path        string
	Size        int64
	IsEncrypted bool
	IsSelected  bool
}

func FindEligibleFiles(mode types.ProcessorMode) ([]string, error) {
	var files []string

	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if isEligible(path, info, mode) {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("failed to scan for eligible files: %w", err)
	}
	return files, nil
}

func isEligible(path string, info os.FileInfo, mode types.ProcessorMode) bool {
	if info.IsDir() || strings.HasPrefix(info.Name(), ".") || isExcluded(path) {
		return false
	}

	isEncrypted := isEncryptedFile(path)
	switch mode {
	case types.ModeEncrypt:
		return !isEncrypted
	case types.ModeDecrypt:
		return isEncrypted
	default:
		return false
	}
}

func isExcluded(path string) bool {
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

func isEncryptedFile(path string) bool {
	return strings.HasSuffix(path, config.FileExtension)
}

func GetOutputPath(inputPath string, mode types.ProcessorMode) string {
	switch mode {
	case types.ModeEncrypt:
		return inputPath + config.FileExtension
	case types.ModeDecrypt:
		return strings.TrimSuffix(inputPath, config.FileExtension)
	default:
		return inputPath
	}
}

func GetFileInfoList(files []string) ([]FileInfo, error) {
	var infos []FileInfo
	for _, filePath := range files {
		stat, err := GetFileInfo(filePath)
		if err != nil {
			return nil, fmt.Errorf("stat failed for %q: %w", filePath, err)
		}
		if stat == nil {
			return nil, fmt.Errorf("file not found: %s", filePath)
		}

		info := FileInfo{
			Path:        filePath,
			Size:        stat.Size(),
			IsEncrypted: isEncryptedFile(filePath),
			IsSelected:  true,
		}
		infos = append(infos, info)
	}
	return infos, nil
}

func Remove(path string) error {
	cleanPath := filepath.Clean(path)

	if err := requireExists(cleanPath); err != nil {
		return fmt.Errorf("cannot remove: %w", err)
	}

	return os.Remove(cleanPath)
}

func CreateFile(path string) (*os.File, error) {
	cleanPath := filepath.Clean(path)

	if err := ensureParentDir(cleanPath); err != nil {
		return nil, err
	}
	return os.Create(cleanPath)
}

func OpenFile(path string) (*os.File, error) {
	cleanPath := filepath.Clean(path)

	f, err := os.Open(cleanPath)
	if err != nil {
		return nil, fmt.Errorf("open failed: %w", err)
	}

	return f, nil
}

func GetFileInfo(path string) (os.FileInfo, error) {
	cleanPath := filepath.Clean(path)
	stat, err := os.Stat(cleanPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("stat failed: %w", err)
	}
	return stat, nil
}

func ValidatePath(path string, mustExist bool) error {
	cleanPath := filepath.Clean(path)

	info, err := GetFileInfo(cleanPath)
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

func requireExists(path string) error {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("not found: %s", path)
		}
		return fmt.Errorf("access failed: %w", err)
	}
	return nil
}

func ensureParentDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "." || dir == "/" {
		return nil
	}
	return os.MkdirAll(dir, 0o750)
}
