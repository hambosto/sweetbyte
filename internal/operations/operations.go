package operations

import (
	"context"
	"fmt"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/files"
	"github.com/hambosto/sweetbyte/internal/header"
	"github.com/hambosto/sweetbyte/internal/kdf"
	"github.com/hambosto/sweetbyte/internal/options"
	"github.com/hambosto/sweetbyte/internal/streaming"
)

type FileOperations interface {
	Encrypt(srcPath, destPath, password string) error
	Decrypt(srcPath, destPath, password string) error
}

type fileOperations struct {
	fileManager files.FileManager
}

func NewFileOperations(fileManager files.FileManager) FileOperations {
	return &fileOperations{fileManager: fileManager}
}

func (o *fileOperations) Encrypt(srcPath, destPath, password string) error {
	srcFile, srcInfo, err := o.fileManager.OpenFile(srcPath)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close()

	destFile, err := o.fileManager.CreateFile(destPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer destFile.Close()

	salt, err := kdf.GetRandomSalt(config.SaltSize)
	if err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	key, err := kdf.Hash([]byte(password), salt)
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}

	originalSize := srcInfo.Size()
	if originalSize < 0 {
		return fmt.Errorf("invalid file size: %d", originalSize)
	}

	h, err := header.NewHeader(uint64(originalSize))
	if err != nil {
		return fmt.Errorf("failed to create header: %w", err)
	}

	headerBytes, err := h.Marshal(salt, key)
	if err != nil {
		return fmt.Errorf("failed to marshal header: %w", err)
	}
	if _, err := destFile.Write(headerBytes); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	streamConfig := streaming.StreamConfig{
		Key:        key,
		Processing: options.Encryption,
		ChunkSize:  config.DefaultChunkSize,
	}

	processor, err := streaming.NewStreamProcessor(streamConfig)
	if err != nil {
		return fmt.Errorf("failed to create stream processor: %w", err)
	}

	if err := processor.Process(context.Background(), srcFile, destFile, originalSize); err != nil {
		return fmt.Errorf("failed to process file: %w", err)
	}

	return nil
}

func (o *fileOperations) Decrypt(srcPath, destPath, password string) error {
	srcFile, _, err := o.fileManager.OpenFile(srcPath)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close()

	magic, err := header.ReadMagic(srcFile)
	if err != nil {
		return fmt.Errorf("failed to read magic bytes: %w", err)
	}

	if !header.VerifyMagic(magic) {
		return fmt.Errorf("invalid magic bytes: not a sweetbyte file")
	}

	salt, err := header.ReadSalt(srcFile)
	if err != nil {
		return fmt.Errorf("failed to read salt: %w", err)
	}

	key, err := kdf.Hash([]byte(password), salt)
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}

	h, err := header.Unmarshal(srcFile, key, magic, salt)
	if err != nil {
		return fmt.Errorf("decryption failed: incorrect password or corrupt file: %w", err)
	}

	destFile, err := o.fileManager.CreateFile(destPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer destFile.Close()

	streamConfig := streaming.StreamConfig{
		Key:        key,
		Processing: options.Decryption,
		ChunkSize:  config.DefaultChunkSize,
	}

	processor, err := streaming.NewStreamProcessor(streamConfig)
	if err != nil {
		return fmt.Errorf("failed to create stream processor: %w", err)
	}

	if err := processor.Process(context.Background(), srcFile, destFile, int64(h.OriginalSize)); err != nil {
		return fmt.Errorf("failed to process file: %w", err)
	}

	return nil
}
