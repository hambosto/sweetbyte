package file

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hambosto/sweetbyte/internal/types"
)

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
