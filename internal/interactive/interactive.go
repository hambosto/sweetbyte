package interactive

import (
	"fmt"
	"os"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/files"
	"github.com/hambosto/sweetbyte/internal/operations"
	"github.com/hambosto/sweetbyte/internal/options"
	"github.com/hambosto/sweetbyte/internal/ui"
)

type Interactive struct {
	fileManager    files.FileManager
	fileOperations operations.FileOperations
	prompt         ui.PromptInput
}

func NewInteractive() *Interactive {
	fileManager := files.NewFileManager(config.OverwritePasses)
	fileOperations := operations.NewFileOperations(fileManager)
	prompt := ui.NewPromptInput(config.PasswordMinLen)
	return &Interactive{
		fileManager:    fileManager,
		prompt:         prompt,
		fileOperations: fileOperations,
	}
}

func (a *Interactive) Run() {
	ui.Clear()
	ui.MoveTopLeft()
	ui.PrintBanner()

	if err := a.runInteractiveLoop(); err != nil {
		fmt.Printf("Application error: %v\n", err)
		os.Exit(1)
	}
}

func (a *Interactive) runInteractiveLoop() error {
	operation, err := a.prompt.GetProcessingMode()
	if err != nil {
		return fmt.Errorf("failed to get processing mode: %w", err)
	}

	eligibleFiles, err := a.getEligibleFiles(operation)
	if err != nil {
		return err
	}

	fileInfos, err := a.fileManager.GetFileInfoList(eligibleFiles)
	if err != nil {
		return fmt.Errorf("failed to get file information: %w", err)
	}
	a.fileManager.ShowFileInfo(fileInfos)

	selectedFile, err := a.prompt.ChooseFile(eligibleFiles)
	if err != nil {
		return fmt.Errorf("failed to select file: %w", err)
	}

	a.fileManager.ShowProcessingInfo(operation, selectedFile)

	if err := a.processFile(selectedFile, operation); err != nil {
		return fmt.Errorf("failed to process file %s: %w", selectedFile, err)
	}

	return nil
}

func (a *Interactive) getEligibleFiles(operation options.ProcessorMode) ([]string, error) {
	eligibleFiles, err := a.fileManager.FindEligibleFiles(operation)
	if err != nil {
		return nil, fmt.Errorf("failed to find eligible files: %w", err)
	}

	if len(eligibleFiles) == 0 {
		return nil, fmt.Errorf("no eligible files found for %s operation", operation)
	}

	return eligibleFiles, nil
}

func (a *Interactive) processFile(inputPath string, mode options.ProcessorMode) error {
	outputPath := a.fileManager.GetOutputPath(inputPath, mode)

	if err := a.fileManager.ValidatePath(inputPath, true); err != nil {
		return fmt.Errorf("source validation failed: %w", err)
	}

	if err := a.fileManager.ValidatePath(outputPath, false); err != nil {
		if confirm, confirmErr := a.prompt.ConfirmFileOverwrite(outputPath); confirmErr != nil || !confirm {
			return fmt.Errorf("operation canceled by user")
		}
	}

	var err error
	switch mode {
	case options.ModeEncrypt:
		err = a.encryptFile(inputPath, outputPath)
	case options.ModeDecrypt:
		err = a.decryptFile(inputPath, outputPath)
	default:
		return fmt.Errorf("unknown processing mode: %v", mode)
	}

	if err != nil {
		return err
	}

	fmt.Println()
	fmt.Printf("File encrypted successfully: %s", outputPath)
	fmt.Println()

	var fileType string
	if mode == options.ModeEncrypt {
		fileType = "original"
	} else {
		fileType = "encrypted"
	}

	if shouldDelete, deleteType, err := a.prompt.ConfirmFileRemoval(inputPath, fileType); err == nil && shouldDelete {
		if err := a.fileManager.Remove(inputPath, deleteType); err != nil {
			return fmt.Errorf("failed to delete source file: %w", err)
		}
		fmt.Printf("Source file deleted: %s", inputPath)
	}

	return nil
}

func (a *Interactive) encryptFile(srcPath, destPath string) error {
	password, err := a.prompt.GetEncryptionPassword()
	if err != nil {
		return fmt.Errorf("password prompt failed: %w", err)
	}

	if err := a.fileOperations.Encrypt(srcPath, destPath, password); err != nil {
		return fmt.Errorf("failed to encrypt %s: %w", srcPath, err)
	}

	return nil
}

func (a *Interactive) decryptFile(srcPath, destPath string) error {
	password, err := a.prompt.GetDecryptionPassword()
	if err != nil {
		return fmt.Errorf("password prompt failed: %w", err)
	}

	if err := a.fileOperations.Decrypt(srcPath, destPath, password); err != nil {
		return fmt.Errorf("failed to decrypt %s: %w", srcPath, err)
	}

	return nil
}
