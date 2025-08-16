package interactive

import (
	"fmt"
	"os"

	"github.com/hambosto/sweetbyte/internal/files"
	"github.com/hambosto/sweetbyte/internal/operations"
	"github.com/hambosto/sweetbyte/internal/options"
	"github.com/hambosto/sweetbyte/internal/ui"
)

// InteractiveApp encapsulates the main interactive application
type InteractiveApp struct {
	terminal    *ui.Terminal
	prompt      *ui.Prompt
	fileManager *files.Manager
	fileFinder  *files.Finder
	encryptor   *operations.Encryptor
	decryptor   *operations.Decryptor
}

// NewInteractiveApp creates a new interactive application instance
func NewInteractiveApp() *InteractiveApp {
	return &InteractiveApp{
		terminal:    ui.NewTerminal(),
		prompt:      ui.NewPrompt(),
		fileManager: files.NewManager(),
		fileFinder:  files.NewFinder(),
		encryptor:   operations.NewEncryptor(),
		decryptor:   operations.NewDecryptor(),
	}
}

// Run executes the main interactive application workflow
func (a *InteractiveApp) Run() {
	// Set up terminal
	a.initializeTerminal()

	// Show banner
	a.terminal.PrintBanner()

	// Main application loop
	if err := a.runInteractiveLoop(); err != nil {
		a.handleError(err)
		os.Exit(1)
	}

	// Cleanup
	a.terminal.Cleanup()
}

// initializeTerminal sets up the terminal for the application
func (a *InteractiveApp) initializeTerminal() {
	a.terminal.Clear()
	a.terminal.MoveTopLeft()
}

// runInteractiveLoop executes the main interactive workflow
func (a *InteractiveApp) runInteractiveLoop() error {
	// Get processing mode from user
	operation, err := a.prompt.GetProcessingMode()
	if err != nil {
		return fmt.Errorf("failed to get processing mode: %w", err)
	}

	// Find eligible files
	eligibleFiles, err := a.getEligibleFiles(operation)
	if err != nil {
		return err
	}

	// Show file information
	fileInfos, err := a.fileFinder.GetFileInfo(eligibleFiles)
	if err != nil {
		return fmt.Errorf("failed to get file information: %w", err)
	}
	a.prompt.ShowFileInfo(fileInfos)

	// Let user choose a file
	selectedFile, err := a.prompt.ChooseFile(eligibleFiles)
	if err != nil {
		return fmt.Errorf("failed to select file: %w", err)
	}

	// Show processing info
	a.prompt.ShowProcessingInfo(operation, selectedFile)

	// Process the selected file
	if err := a.processFile(selectedFile, operation); err != nil {
		return fmt.Errorf("failed to process file '%s': %w", selectedFile, err)
	}

	return nil
}

// handleError handles application errors and displays a concise user-facing message
func (a *InteractiveApp) handleError(err error) {
    // Print a formatted error message. Detailed context is preserved in the error chain.
    a.terminal.PrintError(fmt.Sprintf("Application error: %v", err))
}

// getEligibleFiles retrieves files that can be processed based on the operation mode
func (a *InteractiveApp) getEligibleFiles(operation options.ProcessorMode) ([]string, error) {
	eligibleFiles, err := a.fileFinder.FindEligibleFiles(operation)
	if err != nil {
		return nil, fmt.Errorf("failed to find eligible files: %w", err)
	}

	if len(eligibleFiles) == 0 {
		return nil, fmt.Errorf("no eligible files found for %s operation", operation)
	}

	return eligibleFiles, nil
}

// processFile handles the file processing workflow
func (a *InteractiveApp) processFile(inputPath string, mode options.ProcessorMode) error {
	outputPath := a.fileFinder.GetOutputPath(inputPath, mode)

	// Validate paths
	if err := a.fileManager.ValidatePath(inputPath, true); err != nil {
		return fmt.Errorf("source validation failed: %w", err)
	}

	if err := a.fileManager.ValidatePath(outputPath, false); err != nil {
		if confirm, confirmErr := a.prompt.ConfirmFileOverwrite(outputPath); confirmErr != nil || !confirm {
            return fmt.Errorf("operation canceled by user")
        }
	}

	// Process based on mode
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

	a.prompt.ShowSuccess(fmt.Sprintf("File processed successfully: %s", outputPath))

	// Ask to delete source file
	var fileType string
	if mode == options.ModeEncrypt {
		fileType = "original"
	} else {
		fileType = "encrypted"
	}

	if shouldDelete, deleteType, err := a.prompt.ConfirmFileRemoval(inputPath, fmt.Sprintf("Delete %s file", fileType)); err == nil && shouldDelete {
		if err := a.fileManager.Remove(inputPath, deleteType); err != nil {
			return fmt.Errorf("failed to delete source file: %w", err)
		}
		a.prompt.ShowSuccess(fmt.Sprintf("Source file deleted: %s", inputPath))
	}

	return nil
}

// encryptFile handles file encryption
func (a *InteractiveApp) encryptFile(srcPath, destPath string) error {
	// Get password
	password, err := a.prompt.GetEncryptionPassword()
	if err != nil {
		return fmt.Errorf("password prompt failed: %w", err)
	}

	// Perform encryption
	if err := a.encryptor.EncryptFile(srcPath, destPath, password); err != nil {
		return fmt.Errorf("failed to encrypt '%s': %w", srcPath, err)
	}

	return nil
}

// decryptFile handles file decryption
func (a *InteractiveApp) decryptFile(srcPath, destPath string) error {
	// Get password
	password, err := a.prompt.GetDecryptionPassword()
	if err != nil {
		return fmt.Errorf("password prompt failed: %w", err)
	}

	// Perform decryption
	if err := a.decryptor.DecryptFile(srcPath, destPath, password); err != nil {
		return fmt.Errorf("failed to decrypt '%s': %w", srcPath, err)
	}

	return nil
}
