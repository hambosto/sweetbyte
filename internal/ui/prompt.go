// Package ui provides user interface components and utilities for the SweetByte application.
// This includes terminal manipulation, interactive prompts, and progress bar displays,
// enhancing the user experience in both CLI and interactive modes.
package ui

import (
	"fmt"

	"github.com/AlecAivazis/survey/v2"
	"github.com/hambosto/sweetbyte/internal/files"
	"github.com/hambosto/sweetbyte/internal/options"
	"github.com/hambosto/sweetbyte/internal/utils"
)

// Prompt provides interactive command-line prompts for user input.
// It uses the 'survey' library to create a user-friendly guided experience.
type Prompt struct{}

// NewPrompt creates and returns a new Prompt instance.
// It is an empty struct as its methods directly use survey functions.
func NewPrompt() *Prompt {
	return &Prompt{}
}

// ConfirmFileOverwrite asks the user to confirm if they want to overwrite an existing file.
// Returns true if the user confirms, false otherwise, or an error if the prompt fails.
func (p *Prompt) ConfirmFileOverwrite(path string) (bool, error) {
	var result bool            // Variable to store the user's boolean response.
	prompt := &survey.Confirm{ // Create a confirmation prompt.
		Message: fmt.Sprintf("Output file %s already exists. Overwrite?", path), // Message displayed to the user.
	}

	if err := survey.AskOne(prompt, &result); err != nil { // Execute the prompt and store the result.
		return false, fmt.Errorf("prompt failed: %w", err) // Handle any error during the prompt.
	}

	return result, nil // Return the user's decision.
}

// GetEncryptionPassword prompts the user to enter and confirm an encryption password.
// It ensures that the entered password matches its confirmation before returning.
func (p *Prompt) GetEncryptionPassword() (string, error) {
	password, err := p.getPassword("Enter password:") // Get the first password input.
	if err != nil {
		return "", fmt.Errorf("failed to get password: %w", err) // Handle error from password prompt.
	}

	confirm, err := p.getPassword("Confirm password:") // Get the password confirmation.
	if err != nil {
		return "", fmt.Errorf("failed to confirm password: %w", err) // Handle error from confirmation prompt.
	}

	if password != confirm { // Compare the original and confirmed passwords.
		return "", fmt.Errorf("password mismatch") // Return error if they do not match.
	}

	return password, nil // Return the confirmed password.
}

// GetDecryptionPassword prompts the user to enter a decryption password.
func (p *Prompt) GetDecryptionPassword() (string, error) {
	return p.getPassword("Enter password:") // Delegate to the generic password prompt.
}

// getPassword is a helper function to prompt for a sensitive string (password).
// It uses survey.Password to hide input.
func (p *Prompt) getPassword(message string) (string, error) {
	var password string         // Variable to store the entered password.
	prompt := &survey.Password{ // Create a password input prompt.
		Message: message, // Message displayed to the user.
	}

	if err := survey.AskOne(prompt, &password); err != nil { // Execute the prompt.
		return "", fmt.Errorf("prompt failed: %w", err) // Handle any error during the prompt.
	}

	return password, nil // Return the entered password.
}

// ConfirmFileRemoval asks the user to confirm file deletion and select a deletion method.
// Returns true if confirmed, the chosen DeleteOption, and nil error, or false and error.
func (p *Prompt) ConfirmFileRemoval(path, message string) (bool, options.DeleteOption, error) {
	confirmed, err := p.confirmAction(fmt.Sprintf("%s %s", message, path)) // Confirm the deletion action.
	if err != nil {
		return false, "", fmt.Errorf("failed to confirm file removal: %w", err) // Handle confirmation error.
	}

	if !confirmed { // If the user does not confirm deletion.
		return false, "", nil // Return false, indicating no deletion.
	}

	deleteType, err := p.selectDeleteOption() // Prompt user to select deletion type.
	if err != nil {
		return false, "", fmt.Errorf("failed to select delete option: %w", err) // Handle deletion type selection error.
	}

	return true, deleteType, nil // Return true, the selected deletion type, and nil error.
}

// confirmAction is a generic helper to get a boolean confirmation from the user.
func (p *Prompt) confirmAction(message string) (bool, error) {
	var result bool            // Variable to store the user's boolean response.
	prompt := &survey.Confirm{ // Create a confirmation prompt.
		Message: message, // Message displayed to the user.
	}

	if err := survey.AskOne(prompt, &result); err != nil { // Execute the prompt.
		return false, fmt.Errorf("prompt failed: %w", err) // Handle any error during the prompt.
	}

	return result, nil // Return the user's decision.
}

// selectDeleteOption prompts the user to choose between standard and secure file deletion.
func (p *Prompt) selectDeleteOption() (options.DeleteOption, error) {
	opt := []string{ // Available delete options as strings.
		string(options.DeleteStandard),
		string(options.DeleteSecure),
	}

	selected, err := p.selectFromOptions("Select delete type:", opt) // Use generic selection prompt.
	if err != nil {
		return "", err // Propagate error from selection.
	}

	return options.DeleteOption(selected), nil // Convert selected string to DeleteOption and return.
}

// GetProcessingMode prompts the user to select an operation mode (encrypt or decrypt).
func (p *Prompt) GetProcessingMode() (options.ProcessorMode, error) {
	opt := []string{ // Available processing modes as strings.
		string(options.ModeEncrypt),
		string(options.ModeDecrypt),
	}

	selected, err := p.selectFromOptions("Select Operation:", opt) // Use generic selection prompt.
	if err != nil {
		return "", fmt.Errorf("operation selection failed: %w", err) // Handle selection error.
	}

	return options.ProcessorMode(selected), nil // Convert selected string to ProcessorMode and return.
}

// ChooseFile prompts the user to select a file from a given list of file paths.
// Returns the selected file path or an error if no files are available or selection fails.
func (p *Prompt) ChooseFile(files []string) (string, error) {
	if len(files) == 0 { // Check if the list of files is empty.
		return "", fmt.Errorf("no files available for selection") // Return error if no files to choose from.
	}

	selected, err := p.selectFromOptions("Select file:", files) // Use generic selection prompt.
	if err != nil {
		return "", fmt.Errorf("file selection failed: %w", err) // Handle selection error.
	}

	return selected, nil // Return the selected file path.
}

// selectFromOptions is a generic helper to prompt the user to select one option from a list.
func (p *Prompt) selectFromOptions(message string, options []string) (string, error) {
	var selected string       // Variable to store the selected option.
	prompt := &survey.Select{ // Create a select prompt.
		Message: message, // Message displayed to the user.
		Options: options, // List of options to choose from.
	}

	if err := survey.AskOne(prompt, &selected); err != nil { // Execute the prompt.
		return "", fmt.Errorf("prompt failed: %w", err) // Handle any error during the prompt.
	}

	return selected, nil // Return the selected option.
}

// ShowFileInfo displays formatted information about a list of files, including their size and encryption status.
func (p *Prompt) ShowFileInfo(files []files.FileInfo) {
	if len(files) == 0 { // If no files are provided.
		fmt.Println("No files found.") // Print a message indicating no files.
		return
	}

	fmt.Printf("\nFound %d file(s):\n", len(files)) // Print count of found files.
	for i, file := range files {                    // Iterate through each file and print its info.
		status := "unencrypted" // Default status.
		if file.IsEncrypted {   // Check if file is encrypted.
			status = "encrypted" // Update status if encrypted.
		}

		fmt.Printf("%d. %s (%s, %s)\n", // Print formatted file information.
			i+1,                          // 1-based index.
			file.Path,                    // File path.
			utils.FormatBytes(file.Size), // Formatted file size (e.g., 10 KB).
			status,                       // Encryption status.
		)
	}
	fmt.Println() // Add a newline for better readability.
}

// ShowProcessingInfo displays a message indicating the current operation and the file being processed.
func (p *Prompt) ShowProcessingInfo(mode options.ProcessorMode, file string) {
	operation := "Encrypting"        // Default operation description.
	if mode == options.ModeDecrypt { // Adjust description based on mode.
		operation = "Decrypting"
	}

	fmt.Printf("\n%s file: %s\n", operation, file) // Print the operation and file.
}

// ShowSuccess displays a success message to the console with a checkmark symbol.
func (p *Prompt) ShowSuccess(message string) {
	fmt.Printf("✓ %s\n", message) // Print formatted success message.
}

// ShowWarning displays a warning message to the console with a warning symbol.
func (p *Prompt) ShowWarning(message string) {
	fmt.Printf("⚠ %s\n", message) // Print formatted warning message.
}

// ShowInfo displays an informational message to the console with an info symbol.
func (p *Prompt) ShowInfo(message string) {
	fmt.Printf("ℹ %s\n", message) // Print formatted informational message.
}
