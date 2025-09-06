// Package files provides file management functionalities.
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

// FileInfo represents information about a file.
type FileInfo struct {
	Path        string
	Size        int64
	IsEncrypted bool
	IsEligible  bool
}

// FileManager defines the interface for file management.
type FileManager interface {
	// FindEligibleFiles finds files that are eligible for processing based on the given mode.
	FindEligibleFiles(mode options.ProcessorMode) ([]string, error)
	// IsEncryptedFile checks if a file is encrypted.
	IsEncryptedFile(path string) bool
	// GetOutputPath returns the output path for a given input path and processing mode.
	GetOutputPath(inputPath string, mode options.ProcessorMode) string
	// GetFileInfoList returns a list of FileInfo for the given files.
	GetFileInfoList(files []string) ([]FileInfo, error)
	// Remove removes a file with the given option.
	Remove(path string, option options.DeleteOption) error
	// CreateFile creates a new file.
	CreateFile(path string) (*os.File, error)
	// OpenFile opens a file for reading.
	OpenFile(path string) (*os.File, os.FileInfo, error)
	// GetFileInfo returns information about a file.
	GetFileInfo(path string) (os.FileInfo, error)
	// ValidatePath validates a file path.
	ValidatePath(path string, mustExist bool) error
	// ShowFileInfo displays information about a list of files.
	ShowFileInfo(fileList []FileInfo)
	// ShowProcessingInfo displays information about the file being processed.
	ShowProcessingInfo(mode options.ProcessorMode, filePath string)
}

// fileManager implements the FileManager interface.
type fileManager struct {
	overwritePasses int
}

// NewFileManager creates a new FileManager.
func NewFileManager(passes int) FileManager {
	return &fileManager{overwritePasses: passes}
}

// FindEligibleFiles finds files that are eligible for processing based on the given mode.
func (fm *fileManager) FindEligibleFiles(mode options.ProcessorMode) ([]string, error) {
	var files []string

	// Walk the current directory and find eligible files.
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

// isEligible checks if a file is eligible for processing.
func (fm *fileManager) isEligible(path string, info os.FileInfo, mode options.ProcessorMode) bool {
	// Exclude directories, hidden files, and excluded files.
	if info.IsDir() || strings.HasPrefix(info.Name(), ".") || fm.isExcluded(path) {
		return false
	}
	// Check if the file is encrypted.
	encrypted := strings.HasSuffix(path, config.FileExtension)
	// Check if the file is eligible for the given mode.
	return (mode == options.ModeEncrypt && !encrypted) || (mode == options.ModeDecrypt && encrypted)
}

// isExcluded checks if a file is in the excluded list.
func (fm *fileManager) isExcluded(path string) bool {
	// Check if the file is in an excluded directory.
	for _, dir := range config.ExcludedDirs {
		if strings.Contains(path, dir) {
			return true
		}
	}
	// Check if the file has an excluded extension.
	for _, ext := range config.ExcludedExts {
		if strings.HasSuffix(path, ext) {
			return true
		}
	}
	return false
}

// IsEncryptedFile checks if a file is encrypted.
func (fm *fileManager) IsEncryptedFile(path string) bool {
	return strings.HasSuffix(path, config.FileExtension)
}

// GetOutputPath returns the output path for a given input path and processing mode.
func (fm *fileManager) GetOutputPath(inputPath string, mode options.ProcessorMode) string {
	if mode == options.ModeEncrypt {
		return inputPath + config.FileExtension
	}
	return strings.TrimSuffix(inputPath, config.FileExtension)
}

// GetFileInfoList returns a list of FileInfo for the given files.
func (fm *fileManager) GetFileInfoList(files []string) ([]FileInfo, error) {
	var infos []FileInfo

	// Get information for each file.
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

// Remove removes a file with the given option.
func (fm *fileManager) Remove(path string, opt options.DeleteOption) error {
	path = filepath.Clean(path)

	// Check if the file exists.
	if err := fm.requireExists(path); err != nil {
		return fmt.Errorf("cannot remove: %w", err)
	}

	// Remove the file based on the selected option.
	switch opt {
	case options.DeleteStandard:
		return os.Remove(path)
	case options.DeleteSecure:
		return fm.secureDelete(path)
	default:
		return fmt.Errorf("unsupported delete option: %s", opt)
	}
}

// CreateFile creates a new file.
func (fm *fileManager) CreateFile(path string) (*os.File, error) {
	path = filepath.Clean(path)
	// Ensure the parent directory exists.
	if err := fm.ensureParentDir(path); err != nil {
		return nil, err
	}
	return os.Create(path)
}

// OpenFile opens a file for reading.
func (fm *fileManager) OpenFile(path string) (*os.File, os.FileInfo, error) {
	path = filepath.Clean(path)

	// Open the file.
	f, err := os.Open(path)
	if err != nil {
		return nil, nil, fmt.Errorf("open failed: %w", err)
	}
	// Get file information.
	info, err := f.Stat()
	if err != nil {
		return nil, nil, fmt.Errorf("stat failed: %w", err)
	}
	return f, info, nil
}

// GetFileInfo returns information about a file.
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

// ValidatePath validates a file path.
func (fm *fileManager) ValidatePath(path string, mustExist bool) error {
	info, err := fm.GetFileInfo(path)
	if err != nil {
		return err
	}
	if mustExist {
		// Check if the file exists, is not a directory, and is not empty.
		switch {
		case info == nil:
			return fmt.Errorf("file not found: %s", path)
		case info.IsDir():
			return fmt.Errorf("path is directory: %s", path)
		case info.Size() == 0:
			return fmt.Errorf("file is empty: %s", path)
		}
	} else if info != nil {
		// Check if the output file already exists.
		return fmt.Errorf("output exists: %s", path)
	}
	return nil
}

// secureDelete securely deletes a file by overwriting it with random data.
func (fm *fileManager) secureDelete(path string) error {
	path = filepath.Clean(path)
	// Open the file for writing.
	f, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("secure open failed: %w", err)
	}
	defer f.Close()

	// Get file information.
	stat, err := f.Stat()
	if err != nil {
		return fmt.Errorf("stat failed: %w", err)
	}

	// Overwrite the file with random data multiple times.
	for i := 0; i < fm.overwritePasses; i++ {
		if err := fm.overwriteRandom(f, stat.Size()); err != nil {
			return fmt.Errorf("overwrite pass %d failed: %w", i+1, err)
		}
	}

	// Remove the file.
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove failed: %w", err)
	}
	return nil
}

// overwriteRandom overwrites a file with random data.
func (fm *fileManager) overwriteRandom(f *os.File, size int64) error {
	// Seek to the beginning of the file.
	if _, err := f.Seek(0, 0); err != nil {
		return fmt.Errorf("seek failed: %w", err)
	}
	// Create a buffer for random data.
	buf := make([]byte, 4096)
	left := size

	// Write random data to the file in chunks.
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

// requireExists checks if a file exists.
func (fm *fileManager) requireExists(path string) error {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("not found: %s", path)
		}
		return fmt.Errorf("access failed: %w", err)
	}
	return nil
}

// ShowFileInfo displays information about a list of files.
func (fm *fileManager) ShowFileInfo(files []FileInfo) {
	if len(files) == 0 {
		fmt.Println("No files found.")
		return
	}

	// fmt.Printf("\nFound %d file(s):\n\n", len(files))

	fmt.Println()
	fmt.Printf("Found %d file(s):", len(files))
	fmt.Println()

	for i, fi := range files {
		status := "unencrypted"
		if fi.IsEncrypted {
			status = "encrypted"
		}
		fmt.Printf("%d. %s (%s, %s)\n", i+1, fi.Path, utils.FormatBytes(fi.Size), status)
	}
	fmt.Println()
}

// ShowProcessingInfo displays information about the file being processed.
func (fm *fileManager) ShowProcessingInfo(mode options.ProcessorMode, file string) {
	action := "Encrypting"
	if mode == options.ModeDecrypt {
		action = "Decrypting"
	}
	fmt.Println()
	fmt.Printf("%s file: %s", action, file)
	fmt.Println()
}

// ensureParentDir ensures that the parent directory of a file exists.
func (fm *fileManager) ensureParentDir(path string) error {
	dir := filepath.Dir(path)
	if dir == "." || dir == "/" {
		return nil
	}
	return os.MkdirAll(dir, 0o750)
}
