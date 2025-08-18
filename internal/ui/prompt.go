// Package ui provides components for the user interface of the SweetByte application.
package ui

import (
	"fmt"

	"github.com/AlecAivazis/survey/v2"
	"github.com/hambosto/sweetbyte/internal/files"
	"github.com/hambosto/sweetbyte/internal/options"
	"github.com/hambosto/sweetbyte/internal/utils"
)

// Prompt provides functions for interacting with the user via prompts.
type Prompt struct{}

// NewPrompt creates a new Prompt instance.
func NewPrompt() *Prompt {
	return &Prompt{}
}

// ConfirmFileOverwrite asks the user to confirm overwriting a file.
func (p *Prompt) ConfirmFileOverwrite(path string) (bool, error) {
	var result bool
	prompt := &survey.Confirm{
		Message: fmt.Sprintf("Output file %s already exists. Overwrite?", path),
	}

	// Ask the user for confirmation.
	if err := survey.AskOne(prompt, &result); err != nil {
		return false, fmt.Errorf("prompt failed: %w", err)
	}

	return result, nil
}

// GetEncryptionPassword prompts the user for an encryption password and confirms it.
func (p *Prompt) GetEncryptionPassword() (string, error) {
	// Get the initial password.
	password, err := p.getPassword("Enter password:")
	if err != nil {
		return "", fmt.Errorf("failed to get password: %w", err)
	}

	// Confirm the password.
	confirm, err := p.getPassword("Confirm password:")
	if err != nil {
		return "", fmt.Errorf("failed to confirm password: %w", err)
	}

	// Check if the passwords match.
	if password != confirm {
		return "", fmt.Errorf("password mismatch")
	}

	return password, nil
}

// GetDecryptionPassword prompts the user for a decryption password.
func (p *Prompt) GetDecryptionPassword() (string, error) {
	return p.getPassword("Enter password:")
}

// getPassword prompts the user for a password with a given message.
func (p *Prompt) getPassword(message string) (string, error) {
	var password string
	prompt := &survey.Password{
		Message: message,
	}

	// Ask the user for the password.
	if err := survey.AskOne(prompt, &password); err != nil {
		return "", fmt.Errorf("prompt failed: %w", err)
	}

	return password, nil
}

// ConfirmFileRemoval asks the user to confirm removing a file and the deletion type.
func (p *Prompt) ConfirmFileRemoval(path, message string) (bool, options.DeleteOption, error) {
	// Confirm the removal action.
	confirmed, err := p.confirmAction(fmt.Sprintf("%s %s", message, path))
	if err != nil {
		return false, "", fmt.Errorf("failed to confirm file removal: %w", err)
	}

	// If not confirmed, return.
	if !confirmed {
		return false, "", nil
	}

	// Select the deletion type.
	deleteType, err := p.selectDeleteOption()
	if err != nil {
		return false, "", fmt.Errorf("failed to select delete option: %w", err)
	}

	return true, deleteType, nil
}

// confirmAction asks the user to confirm an action with a given message.
func (p *Prompt) confirmAction(message string) (bool, error) {
	var result bool
	prompt := &survey.Confirm{
		Message: message,
	}

	// Ask the user for confirmation.
	if err := survey.AskOne(prompt, &result); err != nil {
		return false, fmt.Errorf("prompt failed: %w", err)
	}

	return result, nil
}

// selectDeleteOption prompts the user to select a deletion option.
func (p *Prompt) selectDeleteOption() (options.DeleteOption, error) {
	opt := []string{
		string(options.DeleteStandard),
		string(options.DeleteSecure),
	}

	// Select from the available options.
	selected, err := p.selectFromOptions("Select delete type:", opt)
	if err != nil {
		return "", err
	}

	return options.DeleteOption(selected), nil
}

// GetProcessingMode prompts the user to select a processing mode (encrypt or decrypt).
func (p *Prompt) GetProcessingMode() (options.ProcessorMode, error) {
	opt := []string{
		string(options.ModeEncrypt),
		string(options.ModeDecrypt),
	}

	// Select from the available options.
	selected, err := p.selectFromOptions("Select Operation:", opt)
	if err != nil {
		return "", fmt.Errorf("operation selection failed: %w", err)
	}

	return options.ProcessorMode(selected), nil
}

// ChooseFile prompts the user to choose a file from a list of files.
func (p *Prompt) ChooseFile(files []string) (string, error) {
	// If no files are available, return an error.
	if len(files) == 0 {
		return "", fmt.Errorf("no files available for selection")
	}

	// Select from the available files.
	selected, err := p.selectFromOptions("Select file:", files)
	if err != nil {
		return "", fmt.Errorf("file selection failed: %w", err)
	}

	return selected, nil
}

// selectFromOptions prompts the user to select an option from a list.
func (p *Prompt) selectFromOptions(message string, options []string) (string, error) {
	var selected string
	prompt := &survey.Select{
		Message: message,
		Options: options,
	}

	// Ask the user to select an option.
	if err := survey.AskOne(prompt, &selected); err != nil {
		return "", fmt.Errorf("prompt failed: %w", err)
	}

	return selected, nil
}

// ShowFileInfo displays information about a list of files.
func (p *Prompt) ShowFileInfo(files []files.FileInfo) {
	// If no files are found, print a message.
	if len(files) == 0 {
		fmt.Println("No files found.")
		return
	}

	// Print information for each file.
	fmt.Printf("\nFound %d file(s):\n", len(files))
	for i, file := range files {
		status := "unencrypted"
		if file.IsEncrypted {
			status = "encrypted"
		}

		fmt.Printf("%d. %s (%s, %s)\n", i+1, file.Path, utils.FormatBytes(file.Size), status)
	}
	fmt.Println()
}

// ShowProcessingInfo displays information about the current processing operation.
func (p *Prompt) ShowProcessingInfo(mode options.ProcessorMode, file string) {
	operation := "Encrypting"
	if mode == options.ModeDecrypt {
		operation = "Decrypting"
	}

	fmt.Printf("\n%s file: %s\n", operation, file)
}

// ShowSuccess displays a success message.
func (p *Prompt) ShowSuccess(message string) {
	fmt.Printf("✓ %s\n", message)
}

// ShowWarning displays a warning message.
func (p *Prompt) ShowWarning(message string) {
	fmt.Printf("⚠ %s\n", message)
}
