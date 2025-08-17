// Package interactive provides the interactive command-line interface (TUI) for the SweetByte application.
// It guides the user through the process of encrypting and decrypting files step-by-step,
// handling user input, file selection, and operation execution.
package interactive

import (
	"fmt"
	"os"

	"github.com/hambosto/sweetbyte/internal/files"
	"github.com/hambosto/sweetbyte/internal/operations"
	"github.com/hambosto/sweetbyte/internal/options"
	"github.com/hambosto/sweetbyte/internal/ui"
)

// InteractiveApp represents the main structure for the interactive mode of SweetByte.
// It orchestrates various UI components, file management, and core encryption/decryption operations.
type InteractiveApp struct {
	terminal    *ui.Terminal          // Manages terminal interactions like clearing screen and printing messages.
	prompt      *ui.Prompt            // Handles user prompts for input (e.g., passwords, file selection).
	fileManager *files.Manager        // Manages file system operations (e.g., opening, deleting files).
	fileFinder  *files.Finder         // Discovers eligible files for encryption/decryption.
	encryptor   *operations.Encryptor // Performs the file encryption operations.
	decryptor   *operations.Decryptor // Performs the file decryption operations.
}

// NewInteractiveApp creates and returns a new InteractiveApp instance.
// It initializes all necessary components for running the interactive application.
func NewInteractiveApp() *InteractiveApp {
	return &InteractiveApp{
		terminal:    ui.NewTerminal(),          // Initialize the terminal handler.
		prompt:      ui.NewPrompt(),            // Initialize the prompt handler.
		fileManager: files.NewManager(),        // Initialize the file manager.
		fileFinder:  files.NewFinder(),         // Initialize the file finder.
		encryptor:   operations.NewEncryptor(), // Initialize the encryption operations handler.
		decryptor:   operations.NewDecryptor(), // Initialize the decryption operations handler.
	}
}

// Run starts the interactive SweetByte application.
// It initializes the terminal, prints a banner, runs the main interactive loop,
// and handles any errors that occur during the process before cleaning up the terminal.
func (a *InteractiveApp) Run() {
	a.initializeTerminal()   // Prepare the terminal for interactive display.
	a.terminal.PrintBanner() // Display the application banner.

	if err := a.runInteractiveLoop(); err != nil { // Execute the main interactive workflow.
		a.handleError(err) // If an error occurs, log and display it.
		os.Exit(1)         // Exit the application with an error status.
	}

	a.terminal.Cleanup() // Restore terminal settings after the application finishes.
}

// initializeTerminal clears the terminal screen and moves the cursor to the top-left corner.
func (a *InteractiveApp) initializeTerminal() {
	a.terminal.Clear()       // Clear the terminal screen.
	a.terminal.MoveTopLeft() // Move cursor to the beginning.
}

// runInteractiveLoop contains the core logic for the interactive session.
// It guides the user through selecting an operation, choosing files, and processing them.
func (a *InteractiveApp) runInteractiveLoop() error {
	operation, err := a.prompt.GetProcessingMode() // Prompt user to choose between encrypt/decrypt.
	if err != nil {
		return fmt.Errorf("failed to get processing mode: %w", err) // Handle error in getting mode.
	}

	eligibleFiles, err := a.getEligibleFiles(operation) // Find files suitable for the selected operation.
	if err != nil {
		return err // Propagate error if no eligible files are found or an issue occurs.
	}

	fileInfos, err := a.fileFinder.GetFileInfo(eligibleFiles) // Get detailed information for eligible files.
	if err != nil {
		return fmt.Errorf("failed to get file information: %w", err) // Handle error in getting file info.
	}
	a.prompt.ShowFileInfo(fileInfos) // Display file information to the user.

	selectedFile, err := a.prompt.ChooseFile(eligibleFiles) // Prompt user to select a file from the list.
	if err != nil {
		return fmt.Errorf("failed to select file: %w", err) // Handle error in file selection.
	}

	a.prompt.ShowProcessingInfo(operation, selectedFile) // Display information about the chosen operation and file.

	if err := a.processFile(selectedFile, operation); err != nil { // Execute the file processing (encrypt/decrypt).
		return fmt.Errorf("failed to process file '%s': %w", selectedFile, err) // Handle error during file processing.
	}

	return nil // Return nil if the interactive loop completes successfully.
}

// handleError prints the given error message to the terminal.
func (a *InteractiveApp) handleError(err error) {
	a.terminal.PrintError(fmt.Sprintf("Application error: %v", err)) // Print error message using terminal utility.
}

// getEligibleFiles finds and returns a list of files suitable for the specified operation mode.
// It handles cases where no eligible files are found.
func (a *InteractiveApp) getEligibleFiles(operation options.ProcessorMode) ([]string, error) {
	eligibleFiles, err := a.fileFinder.FindEligibleFiles(operation) // Discover files based on the operation (e.g., .swb for decrypt).
	if err != nil {
		return nil, fmt.Errorf("failed to find eligible files: %w", err) // Handle error during file search.
	}

	if len(eligibleFiles) == 0 { // If no files are found for the selected operation.
		return nil, fmt.Errorf("no eligible files found for %s operation", operation) // Return a specific error.
	}

	return eligibleFiles, nil // Return the list of eligible file paths.
}

// processFile orchestrates the actual encryption or decryption of the selected file.
// It determines the output path, validates paths, handles file overwrites, executes
// the core operation, and offers to delete the source file.
func (a *InteractiveApp) processFile(inputPath string, mode options.ProcessorMode) error {
	outputPath := a.fileFinder.GetOutputPath(inputPath, mode) // Determine the appropriate output file path.

	if err := a.fileManager.ValidatePath(inputPath, true); err != nil { // Validate the input file path exists and is readable.
		return fmt.Errorf("source validation failed: %w", err) // Return error if source validation fails.
	}

	if err := a.fileManager.ValidatePath(outputPath, false); err != nil { // Validate if the output path exists (expected to not exist).
		// If output file exists, confirm with the user whether to overwrite.
		if confirm, confirmErr := a.prompt.ConfirmFileOverwrite(outputPath); confirmErr != nil || !confirm {
			return fmt.Errorf("operation canceled by user") // Cancel operation if user declines overwrite or error occurs.
		}
	}

	var err error
	switch mode { // Execute either encryption or decryption based on the selected mode.
	case options.ModeEncrypt:
		err = a.encryptFile(inputPath, outputPath) // Call the encryption routine.
	case options.ModeDecrypt:
		err = a.decryptFile(inputPath, outputPath) // Call the decryption routine.
	default:
		return fmt.Errorf("unknown processing mode: %v", mode) // Handle an unexpected processing mode.
	}

	if err != nil { // If an error occurred during encryption/decryption.
		return err // Propagate the error.
	}

	a.prompt.ShowSuccess(fmt.Sprintf("File processed successfully: %s", outputPath)) // Inform user of success.

	var fileType string
	if mode == options.ModeEncrypt { // Determine the type of source file to be potentially deleted.
		fileType = "original"
	} else {
		fileType = "encrypted"
	}

	// Prompt user to confirm deletion of the source file.
	if shouldDelete, deleteType, err := a.prompt.ConfirmFileRemoval(inputPath, fmt.Sprintf("Delete %s file", fileType)); err == nil && shouldDelete {
		if err := a.fileManager.Remove(inputPath, deleteType); err != nil { // Perform deletion if confirmed.
			return fmt.Errorf("failed to delete source file: %w", err) // Handle error during deletion.
		}
		a.prompt.ShowSuccess(fmt.Sprintf("Source file deleted: %s", inputPath)) // Confirm successful deletion.
	}

	return nil // Return nil on successful file processing.
}

// encryptFile handles the specific logic for encrypting a file in interactive mode.
// It prompts for a password and calls the core encryptor.
func (a *InteractiveApp) encryptFile(srcPath, destPath string) error {
	password, err := a.prompt.GetEncryptionPassword() // Prompt the user to enter the encryption password.
	if err != nil {
		return fmt.Errorf("password prompt failed: %w", err) // Handle password prompt errors.
	}

	if err := a.encryptor.EncryptFile(srcPath, destPath, password); err != nil { // Execute the encryption using the core encryptor.
		return fmt.Errorf("failed to encrypt '%s': %w", srcPath, err) // Handle encryption errors.
	}

	return nil // Return nil on successful encryption.
}

// decryptFile handles the specific logic for decrypting a file in interactive mode.
// It prompts for a password and calls the core decryptor.
func (a *InteractiveApp) decryptFile(srcPath, destPath string) error {
	password, err := a.prompt.GetDecryptionPassword() // Prompt the user to enter the decryption password.
	if err != nil {
		return fmt.Errorf("password prompt failed: %w", err) // Handle password prompt errors.
	}

	if err := a.decryptor.DecryptFile(srcPath, destPath, password); err != nil { // Execute the decryption using the core decryptor.
		return fmt.Errorf("failed to decrypt '%s': %w", srcPath, err) // Handle decryption errors.
	}

	return nil // Return nil on successful decryption.
}
