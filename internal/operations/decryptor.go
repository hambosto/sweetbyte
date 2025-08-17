package operations

import (
	"context"
	"fmt"
	"math"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/files"
	"github.com/hambosto/sweetbyte/internal/header"
	"github.com/hambosto/sweetbyte/internal/keys"
	"github.com/hambosto/sweetbyte/internal/options"
	"github.com/hambosto/sweetbyte/internal/streaming"
)

type Decryptor struct {
	fileManager	*files.Manager
	fileFinder	*files.Finder
}

func NewDecryptor() *Decryptor {
	return &Decryptor{
		fileManager:	files.NewManager(),
		fileFinder:	files.NewFinder(),
	}
}

func (d *Decryptor) DecryptFile(srcPath, destPath, password string) error {
	srcFile, _, err := d.fileManager.OpenFile(srcPath)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close()

	header, err := header.Read(srcFile)
	if err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}

	key, err := keys.Hash([]byte(password), header.Salt())
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}

	if err := header.Verify(key); err != nil {
		return fmt.Errorf("decryption failed: incorrect password or corrupt file: %w", err)
	}

	originalSize := header.OriginalSize()
	if originalSize > math.MaxInt64 {
		return fmt.Errorf("file too large: %d bytes", originalSize)
	}

	destFile, err := d.fileManager.CreateFile(destPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer destFile.Close()

	config := streaming.StreamConfig{
		Key:		key,
		Processing:	options.Decryption,
		Concurrency:	config.MaxConcurrency,
		ChunkSize:	config.DefaultChunkSize,
	}

	processor, err := streaming.NewStreamProcessor(config)
	if err != nil {
		return fmt.Errorf("failed to create stream processor: %w", err)
	}

	if err := processor.Process(context.Background(), srcFile, destFile, int64(originalSize)); err != nil {
		return fmt.Errorf("failed to process file: %w", err)
	}

	return nil
}
