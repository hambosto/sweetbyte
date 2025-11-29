package file

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/gobwas/glob"
	"github.com/hambosto/sweetbyte/internal/config"
)

var (
	exclusionGlobs         []glob.Glob
	exclusionGlobsCompiled bool
)

func isExcluded(path string) bool {
	cleanPath := filepath.Clean(path)
	globs := getCompiledExclusionGlobs()

	for _, g := range globs {
		if g.Match(cleanPath) {
			return true
		}
	}
	return false
}

func getCompiledExclusionGlobs() []glob.Glob {
	if exclusionGlobsCompiled {
		return exclusionGlobs
	}

	for _, pattern := range config.ExcludedPatterns {
		g, err := glob.Compile(pattern, filepath.Separator)
		if err != nil {
			continue
		}
		exclusionGlobs = append(exclusionGlobs, g)
	}
	exclusionGlobsCompiled = true

	return exclusionGlobs
}

func isEncryptedFile(path string) bool {
	return strings.HasSuffix(path, config.FileExtension)
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
