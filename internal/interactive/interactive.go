// Package interactive provides the interactive mode for the SweetByte application.
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

// Interactive represents the interactive application.
type Interactive struct {
	prompt      ui.Prompt
	fileManager files.FileManager
	encryptor   operations.Encryptor
	decryptor   operations.Decryptor
}

// NewInteractive creates a new Interactive.
func NewInteractive() *Interactive {
	fileManager := files.NewFileManager(config.OverwritePasses)
	prompt := ui.NewPrompt(8)
	encryptor := operations.NewFileEncryptor(fileManager)
	decryptor := operations.NewFileDecryptor(fileManager)
	return &Interactive{
		prompt:      prompt,
		fileManager: fileManager,
		encryptor:   encryptor,
		decryptor:   decryptor,
	}
}

// Run starts the interactive application.
func (a *Interactive) Run() {
	ui.Clear()
	ui.MoveTopLeft()
	ui.PrintBanner()

	// Run the main interactive loop.
	if err := a.runInteractiveLoop(); err != nil {
		fmt.Printf("Application error: %v\n", err)
		os.Exit(1)
	}
}

// runInteractiveLoop runs the main interactive loop.
func (a *Interactive) runInteractiveLoop() error {
	// Get the desired operation from the user.
	operation, err := a.prompt.GetProcessingMode()
	if err != nil {
		return fmt.Errorf("failed to get processing mode: %w", err)
	}

	// Get the list of eligible files for the selected operation.
	eligibleFiles, err := a.getEligibleFiles(operation)
	if err != nil {
		return err
	}

	// Get file information for the eligible files.
	fileInfos, err := a.fileManager.GetFileInfoList(eligibleFiles)
	if err != nil {
		return fmt.Errorf("failed to get file information: %w", err)
	}
	a.prompt.ShowFileInfo(fileInfos)

	// Let the user choose a file to process.
	selectedFile, err := a.prompt.ChooseFile(eligibleFiles)
	if err != nil {
		return fmt.Errorf("failed to select file: %w", err)
	}

	a.prompt.ShowProcessingInfo(operation, selectedFile)

	// Process the selected file.
	if err := a.processFile(selectedFile, operation); err != nil {
		return fmt.Errorf("failed to process file %s: %w", selectedFile, err)
	}

	return nil
}

// getEligibleFiles gets the list of eligible files for the selected operation.
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

// processFile processes the selected file.
func (a *Interactive) processFile(inputPath string, mode options.ProcessorMode) error {
	// Get the output path for the file.
	outputPath := a.fileManager.GetOutputPath(inputPath, mode)

	// Validate the input and output paths.
	if err := a.fileManager.ValidatePath(inputPath, true); err != nil {
		return fmt.Errorf("source validation failed: %w", err)
	}

	if err := a.fileManager.ValidatePath(outputPath, false); err != nil {
		if confirm, confirmErr := a.prompt.ConfirmFileOverwrite(outputPath); confirmErr != nil || !confirm {
			return fmt.Errorf("operation canceled by user")
		}
	}

	// Process the file based on the selected mode.
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

	fmt.Printf("\nFile processed successfully: %s\n", outputPath)

	// Ask the user if they want to delete the source file.
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

// encryptFile encrypts the selected file.
func (a *Interactive) encryptFile(srcPath, destPath string) error {
	// Get the encryption password from the user.
	password, err := a.prompt.GetEncryptionPassword()
	if err != nil {
		return fmt.Errorf("password prompt failed: %w", err)
	}

	// Encrypt the file.
	if err := a.encryptor.EncryptFile(srcPath, destPath, password); err != nil {
		return fmt.Errorf("failed to encrypt '%s': %w", srcPath, err)
	}

	return nil
}

// decryptFile decrypts the selected file.
func (a *Interactive) decryptFile(srcPath, destPath string) error {
	// Get the decryption password from the user.
	password, err := a.prompt.GetDecryptionPassword()
	if err != nil {
		return fmt.Errorf("password prompt failed: %w", err)
	}

	// Decrypt the file.
	if err := a.decryptor.DecryptFile(srcPath, destPath, password); err != nil {
		return fmt.Errorf("failed to decrypt '%s': %w", srcPath, err)
	}

	return nil
}
