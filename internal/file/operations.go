package file

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/types"
)

type FileInfo struct {
	Path        string
	Size        int64
	IsEncrypted bool
	IsSelected  bool
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
	infos := make([]FileInfo, 0, len(files))

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
