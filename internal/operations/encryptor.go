package operations

import (
	"context"
	"fmt"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/files"
	"github.com/hambosto/sweetbyte/internal/header"
	"github.com/hambosto/sweetbyte/internal/keys"
	"github.com/hambosto/sweetbyte/internal/options"
	"github.com/hambosto/sweetbyte/internal/streaming"
)

type Encryptor struct {
	fileManager	*files.Manager
	fileFinder	*files.Finder
}

func NewEncryptor() *Encryptor {
	return &Encryptor{
		fileManager:	files.NewManager(),
		fileFinder:	files.NewFinder(),
	}
}

func (e *Encryptor) EncryptFile(srcPath, destPath, password string) error {

	srcFile, srcInfo, err := e.fileManager.OpenFile(srcPath)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close()

	destFile, err := e.fileManager.CreateFile(destPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer destFile.Close()

	salt, err := keys.GetRandomSalt(config.SaltSize)
	if err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	key, err := keys.Hash([]byte(password), salt)
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}

	originalSize := srcInfo.Size()
	if originalSize < 0 {
		return fmt.Errorf("invalid file size: %d", originalSize)
	}

	h, err := header.NewHeader(uint64(originalSize), salt, key)
	if err != nil {
		return fmt.Errorf("failed to create header: %w", err)
	}

	if err := h.Write(destFile); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	config := streaming.StreamConfig{
		Key:		key,
		Processing:	options.Encryption,
		Concurrency:	config.MaxConcurrency,
		ChunkSize:	config.DefaultChunkSize,
	}

	processor, err := streaming.NewStreamProcessor(config)
	if err != nil {
		return fmt.Errorf("failed to create stream processor: %w", err)
	}

	if err := processor.Process(context.Background(), srcFile, destFile, originalSize); err != nil {
		return fmt.Errorf("failed to process file: %w", err)
	}

	return nil
}
