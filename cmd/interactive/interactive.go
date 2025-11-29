package interactive

import (
	"fmt"
	"os"

	"github.com/hambosto/sweetbyte/internal/file"
	"github.com/hambosto/sweetbyte/internal/processor"
	"github.com/hambosto/sweetbyte/internal/types"
	"github.com/hambosto/sweetbyte/internal/ui"
)

func Run() {
	if err := ui.Clear(); err != nil {
		fmt.Printf("failed to clear screen: %v\n", err)
		os.Exit(1)
	}
	ui.PrintBanner()

	if err := runInteractiveLoop(); err != nil {
		fmt.Printf("Application error: %v\n", err)
		os.Exit(1)
	}
}

func runInteractiveLoop() error {
	operation, err := ui.GetProcessingMode()
	if err != nil {
		return fmt.Errorf("failed to get processing mode: %w", err)
	}

	eligibleFiles, err := getEligibleFiles(operation)
	if err != nil {
		return err
	}

	fileInfos, err := file.GetFileInfoList(eligibleFiles)
	if err != nil {
		return fmt.Errorf("failed to get file information: %w", err)
	}

	var filePaths []string
	var fileSizes []int64
	var fileEncrypted []bool

	for _, info := range fileInfos {
		filePaths = append(filePaths, info.Path)
		fileSizes = append(fileSizes, info.Size)
		fileEncrypted = append(fileEncrypted, info.IsEncrypted)
	}

	if err := ui.ShowFileInfo(filePaths, fileSizes, fileEncrypted); err != nil {
		return fmt.Errorf("failed to display file info: %w", err)
	}

	selectedFile, err := ui.ChooseFile(eligibleFiles)
	if err != nil {
		return fmt.Errorf("failed to select file: %w", err)
	}

	if err := processFile(selectedFile, operation); err != nil {
		return fmt.Errorf("failed to process file %s: %w", selectedFile, err)
	}

	return nil
}

func getEligibleFiles(operation types.ProcessorMode) ([]string, error) {
	eligibleFiles, err := file.FindEligibleFiles(operation)
	if err != nil {
		return nil, fmt.Errorf("failed to find eligible files: %w", err)
	}

	if len(eligibleFiles) == 0 {
		return nil, fmt.Errorf("no eligible files found for %s operation", operation)
	}

	return eligibleFiles, nil
}

func processFile(inputPath string, mode types.ProcessorMode) error {
	outputPath := file.GetOutputPath(inputPath, mode)

	if err := file.ValidatePath(inputPath, true); err != nil {
		return fmt.Errorf("source validation failed: %w", err)
	}

	if err := file.ValidatePath(outputPath, false); err != nil {
		if confirm, confirmErr := ui.ConfirmFileOverwrite(outputPath); confirmErr != nil || !confirm {
			return fmt.Errorf("operation canceled by user")
		}
	}

	var err error
	switch mode {
	case types.ModeEncrypt:
		err = encryptFile(inputPath, outputPath)
	case types.ModeDecrypt:
		err = decryptFile(inputPath, outputPath)
	default:
		return fmt.Errorf("unknown processing mode: %v", mode)
	}

	if err != nil {
		return err
	}

	ui.ShowSuccessInfo(mode, outputPath)
	var fileType string
	if mode == types.ModeEncrypt {
		fileType = "original"
	} else {
		fileType = "encrypted"
	}

	if shouldDelete, err := ui.ConfirmFileRemoval(inputPath, fileType); err != nil {
		return fmt.Errorf("failed to confirm file removal: %w", err)
	} else if shouldDelete {
		if err := file.Remove(inputPath); err != nil {
			return fmt.Errorf("failed to delete source file: %w", err)
		}
		ui.ShowSourceDeleted(inputPath)
	}

	return nil
}

func encryptFile(srcPath, destPath string) error {
	password, err := ui.GetEncryptionPassword()
	if err != nil {
		return fmt.Errorf("password prompt failed: %w", err)
	}

	if err := processor.Encryption(srcPath, destPath, password); err != nil {
		return fmt.Errorf("failed to encrypt %s: %w", srcPath, err)
	}

	return nil
}

func decryptFile(srcPath, destPath string) error {
	password, err := ui.GetDecryptionPassword()
	if err != nil {
		return fmt.Errorf("password prompt failed: %w", err)
	}

	if err := processor.Decryption(srcPath, destPath, password); err != nil {
		return fmt.Errorf("failed to decrypt %s: %w", srcPath, err)
	}

	return nil
}
