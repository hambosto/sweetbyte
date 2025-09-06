// Package files provides file system operations for the SweetByte application.
package files

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/options"
	"github.com/hambosto/sweetbyte/internal/utils"
)

// FileInfo holds metadata about a file.
type FileInfo struct {
	Path        string
	Size        int64
	IsEncrypted bool
	IsEligible  bool
}

// FileManager defines the interface for file operations.
type FileManager interface {
	FindEligibleFiles(mode options.ProcessorMode) ([]string, error)
	IsEncryptedFile(path string) bool
	GetOutputPath(inputPath string, mode options.ProcessorMode) string
	GetFileInfoList(files []string) ([]FileInfo, error)
	Remove(path string, option options.DeleteOption) error
	CreateFile(path string) (*os.File, error)
	OpenFile(path string) (*os.File, os.FileInfo, error)
	GetFileInfo(path string) (os.FileInfo, error)
	ValidatePath(path string, mustExist bool) error
	ShowFileInfo(fileList []FileInfo)
	ShowProcessingInfo(mode options.ProcessorMode, filePath string)
}

// fileManager implements FileManager and provides file utilities.
type fileManager struct {
	overwritePasses int
}

// NewManager returns a new FileManager with the given overwrite passes.
func NewFileManager(passes int) FileManager {
	return &fileManager{overwritePasses: passes}
}

// FindEligibleFiles scans the current directory for files eligible for the given mode.
func (fm *fileManager) FindEligibleFiles(mode options.ProcessorMode) ([]string, error) {
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

// isEligible checks if a file can be processed based on mode and exclusions.
func (fm *fileManager) isEligible(path string, info os.FileInfo, mode options.ProcessorMode) bool {
	if info.IsDir() || strings.HasPrefix(info.Name(), ".") || fm.isExcluded(path) {
		return false
	}
	encrypted := strings.HasSuffix(path, config.FileExtension)
	return (mode == options.ModeEncrypt && !encrypted) || (mode == options.ModeDecrypt && encrypted)
}

// isExcluded returns true if the path matches excluded dirs or extensions.
func (fm *fileManager) isExcluded(path string) bool {
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

// IsEncryptedFile checks if the file ends with the encrypted extension.
func (fm *fileManager) IsEncryptedFile(path string) bool {
	return strings.HasSuffix(path, config.FileExtension)
}

// GetOutputPath returns the processed output path for the given mode.
func (fm *fileManager) GetOutputPath(inputPath string, mode options.ProcessorMode) string {
	if mode == options.ModeEncrypt {
		return inputPath + config.FileExtension
	}
	return strings.TrimSuffix(inputPath, config.FileExtension)
}

// GetFileInfoList returns metadata for the given files.
func (fm *fileManager) GetFileInfoList(files []string) ([]FileInfo, error) {
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

// Remove deletes a file using the provided option.
func (fm *fileManager) Remove(path string, opt options.DeleteOption) error {
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

// CreateFile creates a new file, ensuring parent directories exist.
func (fm *fileManager) CreateFile(path string) (*os.File, error) {
	path = filepath.Clean(path)
	if err := fm.ensureParentDir(path); err != nil {
		return nil, err
	}
	return os.Create(path)
}

// OpenFile opens a file and returns its handle and info.
func (fm *fileManager) OpenFile(path string) (*os.File, os.FileInfo, error) {
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

// GetFileInfo retrieves file info or nil if it does not exist.
func (fm *fileManager) GetFileInfo(path string) (os.FileInfo, error) {
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

// ValidatePath validates a path for existence or non-existence.
func (fm *fileManager) ValidatePath(path string, mustExist bool) error {
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

// secureDelete overwrites and removes a file.
func (fm *fileManager) secureDelete(path string) error {
	path = filepath.Clean(path)
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("secure open failed: %w", err)
	}
	defer f.Close() //nolint:errcheck

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

// overwriteRandom writes random data across the file.
func (fm *fileManager) overwriteRandom(f *os.File, size int64) error {
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

// requireExists ensures a file exists.
func (fm *fileManager) requireExists(path string) error {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("not found: %s", path)
		}
		return fmt.Errorf("access failed: %w", err)
	}
	return nil
}

// ShowFileInfo prints metadata about files.
func (fm *fileManager) ShowFileInfo(files []FileInfo) {
	if len(files) == 0 {
		fmt.Println("No files found.")
		return
	}
	fmt.Printf("\nFound %d file(s):\n\n", len(files))
	for i, fi := range files {
		status := "unencrypted"
		if fi.IsEncrypted {
			status = "encrypted"
		}
		fmt.Printf("%d. %s (%s, %s)\n",
			i+1, fi.Path, utils.FormatBytes(fi.Size), status)
	}
	fmt.Println()
}

// ShowProcessingInfo displays progress of current operation.
func (fm *fileManager) ShowProcessingInfo(mode options.ProcessorMode, file string) {
	action := "Encrypting"
	if mode == options.ModeDecrypt {
		action = "Decrypting"
	}
	fmt.Printf("\n%s file: %s\n", action, file)
}

// ensureParentDir creates parent directories if needed.
func (fm *fileManager) ensureParentDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "." || dir == "/" {
		return nil
	}
	return os.MkdirAll(dir, 0o750)
}
