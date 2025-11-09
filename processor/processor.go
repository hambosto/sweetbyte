package processor

import (
	"context"
	"fmt"

	"sweetbyte/derive"
	"sweetbyte/filemanager"
	"sweetbyte/header"
	"sweetbyte/stream"
	"sweetbyte/types"
)

type Processor struct {
	fileManager *filemanager.FileManager
}

func NewProcessor(fileManager *filemanager.FileManager) *Processor {
	return &Processor{fileManager: fileManager}
}

func (p *Processor) Encrypt(srcPath, destPath, password string) error {
	srcFile, srcInfo, err := p.fileManager.OpenFile(srcPath)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close() //nolint:errcheck

	destFile, err := p.fileManager.CreateFile(destPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer destFile.Close() //nolint:errcheck

	salt, err := derive.GetRandomSalt(derive.ArgonSaltLen)
	if err != nil {
		return fmt.Errorf("failed to generate salt: %w", err)
	}

	key, err := derive.Hash([]byte(password), salt)
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}

	originalSize := srcInfo.Size()
	if originalSize <= 0 {
		return fmt.Errorf("cannot encrypt a file with zero or negative size")
	}

	h, err := header.NewHeader()
	if err != nil {
		return fmt.Errorf("failed to create header: %w", err)
	}
	h.SetOriginalSize(uint64(originalSize))
	h.SetProtected(true)

	headerBytes, err := h.Marshal(salt, key)
	if err != nil {
		return fmt.Errorf("failed to marshal header: %w", err)
	}

	if _, err := destFile.Write(headerBytes); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	processor, err := stream.NewStreamProcessor(key, types.Encryption)
	if err != nil {
		return fmt.Errorf("failed to create stream processor: %w", err)
	}

	if err := processor.Process(context.Background(), srcFile, destFile, originalSize); err != nil {
		return fmt.Errorf("failed to process file: %w", err)
	}

	return nil
}

func (p *Processor) Decrypt(srcPath, destPath, password string) error {
	srcFile, _, err := p.fileManager.OpenFile(srcPath)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}
	defer srcFile.Close() //nolint:errcheck

	h, err := header.NewHeader()
	if err != nil {
		return fmt.Errorf("failed to create header: %w", err)
	}

	if err := h.Unmarshal(srcFile); err != nil {
		return fmt.Errorf("failed to unmarshal header: %w", err)
	}

	salt, err := h.Salt()
	if err != nil {
		return fmt.Errorf("failed to get salt from header: %w", err)
	}

	key, err := derive.Hash([]byte(password), salt)
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}

	if err := h.Verify(key); err != nil {
		return fmt.Errorf("decryption failed: incorrect password or corrupt file: %w", err)
	}

	if !h.IsProtected() {
		return fmt.Errorf("file is not protected")
	}

	destFile, err := p.fileManager.CreateFile(destPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}
	defer destFile.Close() //nolint:errcheck

	processor, err := stream.NewStreamProcessor(key, types.Decryption)
	if err != nil {
		return fmt.Errorf("failed to create stream processor: %w", err)
	}

	originalSize := h.GetOriginalSize()
	if originalSize > uint64(int64(^uint64(0)>>1)) { // Check if it exceeds max int64
		return fmt.Errorf("original size exceeds maximum allowed size for processing: %d", originalSize)
	}
	if err := processor.Process(context.Background(), srcFile, destFile, int64(originalSize)); err != nil {
		return fmt.Errorf("failed to process file: %w", err)
	}

	return nil
}
