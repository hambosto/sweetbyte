package ui

import (
	"fmt"

	"github.com/AlecAivazis/survey/v2"
	"github.com/hambosto/sweetbyte/internal/files"
	"github.com/hambosto/sweetbyte/internal/options"
	"github.com/hambosto/sweetbyte/internal/utils"
)

// Prompt provides methods for interactive command-line prompts
type Prompt struct{}

// NewPrompt creates a new Prompt instance
func NewPrompt() *Prompt {
	return &Prompt{}
}

// ConfirmFileOverwrite prompts the user to confirm overwriting an existing file
func (p *Prompt) ConfirmFileOverwrite(path string) (bool, error) {
	var result bool
	prompt := &survey.Confirm{
		Message: fmt.Sprintf("Output file %s already exists. Overwrite?", path),
	}

	if err := survey.AskOne(prompt, &result); err != nil {
		return false, fmt.Errorf("prompt failed: %w", err)
	}

	return result, nil
}

// GetEncryptionPassword prompts for and confirms a password for encryption
func (p *Prompt) GetEncryptionPassword() (string, error) {
	password, err := p.getPassword("Enter password:")
	if err != nil {
		return "", fmt.Errorf("failed to get password: %w", err)
	}

	confirm, err := p.getPassword("Confirm password:")
	if err != nil {
		return "", fmt.Errorf("failed to confirm password: %w", err)
	}

	if password != confirm {
		return "", fmt.Errorf("password mismatch")
	}

	return password, nil
}

// GetDecryptionPassword prompts for a password for decryption
func (p *Prompt) GetDecryptionPassword() (string, error) {
	return p.getPassword("Enter password:")
}

// getPassword is a helper method to prompt for a password
func (p *Prompt) getPassword(message string) (string, error) {
	var password string
	prompt := &survey.Password{
		Message: message,
	}

	if err := survey.AskOne(prompt, &password); err != nil {
		return "", fmt.Errorf("prompt failed: %w", err)
	}

	return password, nil
}

// ConfirmFileRemoval prompts for confirmation and deletion method for file removal
func (p *Prompt) ConfirmFileRemoval(path, message string) (bool, options.DeleteOption, error) {
	confirmed, err := p.confirmAction(fmt.Sprintf("%s %s", message, path))
	if err != nil {
		return false, "", fmt.Errorf("failed to confirm file removal: %w", err)
	}

	if !confirmed {
		return false, "", nil
	}

	deleteType, err := p.selectDeleteOption()
	if err != nil {
		return false, "", fmt.Errorf("failed to select delete option: %w", err)
	}

	return true, deleteType, nil
}

// confirmAction is a helper method for yes/no confirmation prompts
func (p *Prompt) confirmAction(message string) (bool, error) {
	var result bool
	prompt := &survey.Confirm{
		Message: message,
	}

	if err := survey.AskOne(prompt, &result); err != nil {
		return false, fmt.Errorf("prompt failed: %w", err)
	}

	return result, nil
}

// selectDeleteOption prompts the user to select a deletion method
func (p *Prompt) selectDeleteOption() (options.DeleteOption, error) {
	opt := []string{
		string(options.DeleteStandard),
		string(options.DeleteSecure),
	}

	selected, err := p.selectFromOptions("Select delete type:", opt)
	if err != nil {
		return "", err
	}

	return options.DeleteOption(selected), nil
}

// GetProcessingMode prompts the user to select a processing operation
func (p *Prompt) GetProcessingMode() (options.ProcessorMode, error) {
	opt := []string{
		string(options.ModeEncrypt),
		string(options.ModeDecrypt),
	}

	selected, err := p.selectFromOptions("Select Operation:", opt)
	if err != nil {
		return "", fmt.Errorf("operation selection failed: %w", err)
	}

	return options.ProcessorMode(selected), nil
}

// ChooseFile prompts the user to select a file from the provided list
func (p *Prompt) ChooseFile(files []string) (string, error) {
	if len(files) == 0 {
		return "", fmt.Errorf("no files available for selection")
	}

	selected, err := p.selectFromOptions("Select file:", files)
	if err != nil {
		return "", fmt.Errorf("file selection failed: %w", err)
	}

	return selected, nil
}

// selectFromOptions is a helper method for selection prompts
func (p *Prompt) selectFromOptions(message string, options []string) (string, error) {
	var selected string
	prompt := &survey.Select{
		Message: message,
		Options: options,
	}

	if err := survey.AskOne(prompt, &selected); err != nil {
		return "", fmt.Errorf("prompt failed: %w", err)
	}

	return selected, nil
}

// ShowFileInfo displays information about files to be processed
func (p *Prompt) ShowFileInfo(files []files.FileInfo) {
	if len(files) == 0 {
		fmt.Println("No files found.")
		return
	}

	fmt.Printf("\nFound %d file(s):\n", len(files))
	for i, file := range files {
		status := "unencrypted"
		if file.IsEncrypted {
			status = "encrypted"
		}

		fmt.Printf("%d. %s (%s, %s)\n",
			i+1,
			file.Path,
			utils.FormatBytes(file.Size),
			status,
		)
	}
	fmt.Println()
}

// ShowProcessingInfo displays information about the processing pipeline
func (p *Prompt) ShowProcessingInfo(mode options.ProcessorMode, file string) {
	operation := "Encrypting"
	if mode == options.ModeDecrypt {
		operation = "Decrypting"
	}

	fmt.Printf("\n%s file: %s\n", operation, file)
}

// ShowSuccess displays a success message to the user
func (p *Prompt) ShowSuccess(message string) {
	fmt.Printf("✓ %s\n", message)
}

// ShowWarning displays a warning message to the user
func (p *Prompt) ShowWarning(message string) {
	fmt.Printf("⚠ %s\n", message)
}

// ShowInfo displays an informational message to the user
func (p *Prompt) ShowInfo(message string) {
	fmt.Printf("ℹ %s\n", message)
}
