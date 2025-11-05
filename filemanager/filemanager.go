package filemanager

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"sweetbyte/config"
	"sweetbyte/options"
)

type FileInfo struct {
	Path        string
	Size        int64
	IsEncrypted bool
	IsEligible  bool
}

type FileManager struct {
	overwritePasses int
}

func NewFileManager(passes int) *FileManager {
	return &FileManager{overwritePasses: passes}
}

func (fm *FileManager) FindEligibleFiles(mode options.ProcessorMode) ([]string, error) {
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

func (fm *FileManager) isEligible(path string, info os.FileInfo, mode options.ProcessorMode) bool {
	if info.IsDir() || strings.HasPrefix(info.Name(), ".") || fm.isExcluded(path) {
		return false
	}

	encrypted := strings.HasSuffix(path, config.FileExtension)
	return (mode == options.ModeEncrypt && !encrypted) || (mode == options.ModeDecrypt && encrypted)
}

func (fm *FileManager) isExcluded(path string) bool {
	for _, dir := range config.ExcludedDirs {
		if strings.HasPrefix(path, dir) {
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

func (fm *FileManager) IsEncryptedFile(path string) bool {
	return strings.HasSuffix(path, config.FileExtension)
}

func (fm *FileManager) GetOutputPath(inputPath string, mode options.ProcessorMode) string {
	if mode == options.ModeEncrypt {
		return inputPath + config.FileExtension
	}
	return strings.TrimSuffix(inputPath, config.FileExtension)
}

func (fm *FileManager) GetFileInfoList(files []string) ([]FileInfo, error) {
	var infos []FileInfo
	for _, f := range files {
		stat, err := os.Stat(f)
		if err != nil {
			return nil, fmt.Errorf("stat failed for %q: %w", f, err)
		}
		infos = append(infos, FileInfo{
			Path:        f,
			Size:        stat.Size(),
			IsEncrypted: fm.IsEncryptedFile(f),
			IsEligible:  true,
		})
	}
	return infos, nil
}

func (fm *FileManager) Remove(path string, opt options.DeleteOption) error {
	path = filepath.Clean(path)

	if err := fm.requireExists(path); err != nil {
		return fmt.Errorf("cannot remove: %w", err)
	}

	switch opt {
	case options.DeleteStandard:
		return os.Remove(path)
	case options.DeleteSecure:
		return fm.secureDelete(path)
	default:
		return fmt.Errorf("unsupported delete option: %s", opt)
	}
}

func (fm *FileManager) CreateFile(path string) (*os.File, error) {
	path = filepath.Clean(path)

	if err := fm.ensureParentDir(path); err != nil {
		return nil, err
	}
	return os.Create(path)
}

func (fm *FileManager) OpenFile(path string) (*os.File, os.FileInfo, error) {
	path = filepath.Clean(path)

	f, err := os.Open(path)
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
	path = filepath.Clean(path)
	stat, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("stat failed: %w", err)
	}
	return stat, nil
}

func (fm *FileManager) ValidatePath(path string, mustExist bool) error {
	info, err := fm.GetFileInfo(path)
	if err != nil {
		return err
	}
	if mustExist {
		switch {
		case info == nil:
			return fmt.Errorf("file not found: %s", path)
		case info.IsDir():
			return fmt.Errorf("path is directory: %s", path)
		case info.Size() == 0:
			return fmt.Errorf("file is empty: %s", path)
		}
	} else if info != nil {
		return fmt.Errorf("output exists: %s", path)
	}
	return nil
}

func (fm *FileManager) secureDelete(path string) error {
	path = filepath.Clean(path)

	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("secure open failed: %w", err)
	}
	defer f.Close()

	stat, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat failed: %w", err)
	}

	for i := 0; i < fm.overwritePasses; i++ {
		if err := fm.overwriteRandom(f, stat.Size()); err != nil {
			return fmt.Errorf("overwrite pass %d failed: %w", i+1, err)
		}
	}

	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove failed: %w", err)
	}
	return nil
}

func (fm *FileManager) overwriteRandom(f *os.File, size int64) error {
	if _, err := f.Seek(0, 0); err != nil {
		return fmt.Errorf("seek failed: %w", err)
	}

	buf := make([]byte, 4096)
	left := size

	for left > 0 {
		chunk := min(left, int64(len(buf)))
		if _, err := rand.Read(buf[:chunk]); err != nil {
			return fmt.Errorf("rand read failed: %w", err)
		}
		if _, err := f.Write(buf[:chunk]); err != nil {
			return fmt.Errorf("write failed: %w", err)
		}
		left -= chunk
	}
	return f.Sync()
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
