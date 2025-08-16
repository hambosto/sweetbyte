package interactive

import (
	"fmt"
	"os"

	"github.com/hambosto/sweetbyte/internal/files"
	"github.com/hambosto/sweetbyte/internal/operations"
	"github.com/hambosto/sweetbyte/internal/options"
	"github.com/hambosto/sweetbyte/internal/ui"
)

// InteractiveApp orchestrates the user-guided encryption and decryption workflow.
// It manages the terminal UI, user prompts, and file operations.
type InteractiveApp struct {
	terminal    *ui.Terminal
	prompt      *ui.Prompt
	fileManager *files.Manager
	fileFinder  *files.Finder
	encryptor   *operations.Encryptor
	decryptor   *operations.Decryptor
}

// NewInteractiveApp creates and initializes a new InteractiveApp instance.
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

// Run starts and manages the entire interactive session.
// It initializes the terminal, runs the main application loop,
// and handles graceful shutdown and error reporting.
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

// initializeTerminal prepares the terminal for the application by clearing it
// and positioning the cursor at the top-left.
func (a *InteractiveApp) initializeTerminal() {
	a.terminal.Clear()
	a.terminal.MoveTopLeft()
}

// runInteractiveLoop contains the main logic for the interactive session.
// It guides the user from selecting an operation to processing the file.
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

// handleError displays a user-friendly error message in the terminal.
// It ensures that the user is informed of failures without being overwhelmed by technical details.
func (a *InteractiveApp) handleError(err error) {
    // Print a formatted error message. Detailed context is preserved in the error chain.
    a.terminal.PrintError(fmt.Sprintf("Application error: %v", err))
}

// getEligibleFiles finds files in the current directory that are suitable
// for the selected operation (e.g., .swb files for decryption).
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

// processFile orchestrates the core logic for a single file operation.
// It validates paths, performs the encryption or decryption, and handles the
// optional deletion of the source file upon completion.
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

// encryptFile manages the encryption of a single file.
// It prompts the user for a password and then calls the core encryption logic.
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

// decryptFile manages the decryption of a single file.
// It prompts the user for a password and then calls the core decryption logic.
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
