package processor

import (
	"context"
	"fmt"

	"github.com/hambosto/sweetbyte/internal/derive"
	"github.com/hambosto/sweetbyte/internal/file"
	"github.com/hambosto/sweetbyte/internal/header"
	"github.com/hambosto/sweetbyte/internal/stream"
	"github.com/hambosto/sweetbyte/internal/types"
)

func Encryption(srcPath, destPath, password string) error {
	srcFile, err := file.OpenFile(srcPath)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}

	destFile, err := file.CreateFile(destPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}

	srcInfo, err := file.GetFileInfo(srcPath)
	if err != nil {
		return fmt.Errorf("failed to get file info: %w", err)
	}

	salt, err := derive.GetRandomBytes(derive.ArgonSaltLen)
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

	fileHeader, err := header.NewHeader()
	if err != nil {
		return fmt.Errorf("failed to create header: %w", err)
	}
	fileHeader.SetOriginalSize(uint64(originalSize))
	fileHeader.SetProtected(true)

	headerBytes, err := fileHeader.Marshal(salt, key)
	if err != nil {
		return fmt.Errorf("failed to marshal header: %w", err)
	}

	if _, err := destFile.Write(headerBytes); err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}

	pipeline, err := stream.NewPipeline(key, types.Encryption)
	if err != nil {
		return fmt.Errorf("failed to create stream pipeline: %w", err)
	}

	if err := pipeline.Process(context.Background(), srcFile, destFile, originalSize); err != nil {
		return fmt.Errorf("failed to process file: %w", err)
	}

	return nil
}

func Decryption(srcPath, destPath, password string) error {
	srcFile, err := file.OpenFile(srcPath)
	if err != nil {
		return fmt.Errorf("failed to open source file: %w", err)
	}

	fileHeader, err := header.NewHeader()
	if err != nil {
		return fmt.Errorf("failed to create header: %w", err)
	}

	if err := fileHeader.Unmarshal(srcFile); err != nil {
		return fmt.Errorf("failed to unmarshal header: %w", err)
	}

	salt, err := fileHeader.Salt()
	if err != nil {
		return fmt.Errorf("failed to get salt from header: %w", err)
	}

	key, err := derive.Hash([]byte(password), salt)
	if err != nil {
		return fmt.Errorf("failed to derive key: %w", err)
	}

	if err := fileHeader.Verify(key); err != nil {
		return fmt.Errorf("decryption failed: incorrect password or corrupt file: %w", err)
	}

	if !fileHeader.IsProtected() {
		return fmt.Errorf("file is not protected")
	}

	destFile, err := file.CreateFile(destPath)
	if err != nil {
		return fmt.Errorf("failed to create destination file: %w", err)
	}

	pipeline, err := stream.NewPipeline(key, types.Decryption)
	if err != nil {
		return fmt.Errorf("failed to create stream pipeline: %w", err)
	}

	originalSize := fileHeader.GetOriginalSize()
	if originalSize <= 0 {
		return fmt.Errorf("cannot decrypt a file with zero or negative size")
	}

	if err := pipeline.Process(context.Background(), srcFile, destFile, originalSize); err != nil {
		return fmt.Errorf("failed to process file: %w", err)
	}

	return nil
}
