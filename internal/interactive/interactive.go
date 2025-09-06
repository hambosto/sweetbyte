// Package interactive provides the interactive mode for the application.
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

// Interactive handles the application's interactive mode logic.
type Interactive struct {
	fileManager    files.FileManager
	fileOperations operations.FileOperations
	prompt         ui.PromptInput
}

// NewInteractive creates a new Interactive instance with its dependencies.
func NewInteractive() *Interactive {
	// Initialize dependencies.
	fileManager := files.NewFileManager(config.OverwritePasses)
	fileOperations := operations.NewFileOperations(fileManager)
	prompt := ui.NewPromptInput(config.PasswordMinLen)
	return &Interactive{
		fileManager:    fileManager,
		prompt:         prompt,
		fileOperations: fileOperations,
	}
}

// Run starts the interactive mode.
func (a *Interactive) Run() {
	// Clear the screen, move the cursor to the top left, and print the banner.
	ui.Clear()
	ui.MoveTopLeft()
	ui.PrintBanner()

	// Run the interactive loop.
	if err := a.runInteractiveLoop(); err != nil {
		fmt.Printf("Application error: %v\n", err)
		os.Exit(1)
	}
}

// runInteractiveLoop runs the main loop of the interactive mode.
func (a *Interactive) runInteractiveLoop() error {
	// Get the desired operation from the user.
	operation, err := a.prompt.GetProcessingMode()
	if err != nil {
		return fmt.Errorf("failed to get processing mode: %w", err)
	}

	// Find eligible files for the selected operation.
	eligibleFiles, err := a.getEligibleFiles(operation)
	if err != nil {
		return err
	}

	// Get and display file information.
	fileInfos, err := a.fileManager.GetFileInfoList(eligibleFiles)
	if err != nil {
		return fmt.Errorf("failed to get file information: %w", err)
	}
	a.fileManager.ShowFileInfo(fileInfos)

	// Let the user choose a file to process.
	selectedFile, err := a.prompt.ChooseFile(eligibleFiles)
	if err != nil {
		return fmt.Errorf("failed to select file: %w", err)
	}

	// Show processing information.
	a.fileManager.ShowProcessingInfo(operation, selectedFile)

	// Process the selected file.
	if err := a.processFile(selectedFile, operation); err != nil {
		return fmt.Errorf("failed to process file %s: %w", selectedFile, err)
	}

	return nil
}

// getEligibleFiles finds files that are eligible for the selected operation.
func (a *Interactive) getEligibleFiles(operation options.ProcessorMode) ([]string, error) {
	// Find eligible files.
	eligibleFiles, err := a.fileManager.FindEligibleFiles(operation)
	if err != nil {
		return nil, fmt.Errorf("failed to find eligible files: %w", err)
	}

	// Ensure there are eligible files.
	if len(eligibleFiles) == 0 {
		return nil, fmt.Errorf("no eligible files found for %s operation", operation)
	}

	return eligibleFiles, nil
}

// processFile processes the selected file.
func (a *Interactive) processFile(inputPath string, mode options.ProcessorMode) error {
	// Get the output path for the file.
	outputPath := a.fileManager.GetOutputPath(inputPath, mode)

	// Validate the source file.
	if err := a.fileManager.ValidatePath(inputPath, true); err != nil {
		return fmt.Errorf("source validation failed: %w", err)
	}

	// Check if the output file already exists and ask for confirmation to overwrite.
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

	fmt.Println()
	fmt.Printf("File encrypted successfully: %s", outputPath)
	fmt.Println()

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

// encryptFile encrypts the given file.
func (a *Interactive) encryptFile(srcPath, destPath string) error {
	// Get the encryption password from the user.
	password, err := a.prompt.GetEncryptionPassword()
	if err != nil {
		return fmt.Errorf("password prompt failed: %w", err)
	}

	// Encrypt the file.
	if err := a.fileOperations.Encrypt(srcPath, destPath, password); err != nil {
		return fmt.Errorf("failed to encrypt %s: %w", srcPath, err)
	}

	return nil
}

// decryptFile decrypts the given file.
func (a *Interactive) decryptFile(srcPath, destPath string) error {
	// Get the decryption password from the user.
	password, err := a.prompt.GetDecryptionPassword()
	if err != nil {
		return fmt.Errorf("password prompt failed: %w", err)
	}

	// Decrypt the file.
	if err := a.fileOperations.Decrypt(srcPath, destPath, password); err != nil {
		return fmt.Errorf("failed to decrypt %s: %w", srcPath, err)
	}

	return nil
}
