// Package ui provides user interface functionalities.
package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/hambosto/sweetbyte/internal/options"
)

// PromptInput defines the interface for user input prompts.
type PromptInput interface {
	// ConfirmFileOverwrite asks the user to confirm overwriting a file.
	ConfirmFileOverwrite(path string) (bool, error)
	// GetEncryptionPassword prompts the user for an encryption password.
	GetEncryptionPassword() (string, error)
	// GetDecryptionPassword prompts the user for a decryption password.
	GetDecryptionPassword() (string, error)
	// ConfirmFileRemoval asks the user to confirm removing a file.
	ConfirmFileRemoval(path, fileType string) (bool, options.DeleteOption, error)
	// GetProcessingMode prompts the user to select a processing mode.
	GetProcessingMode() (options.ProcessorMode, error)
	// ChooseFile prompts the user to choose a file from a list.
	ChooseFile(fileList []string) (string, error)
}

// promptInput implements the PromptInput interface.
type promptInput struct {
	passwordMinLength int
}

// NewPromptInput creates a new PromptInput.
func NewPromptInput(passwordMinLength int) PromptInput {
	return &promptInput{passwordMinLength: passwordMinLength}
}

// ConfirmFileOverwrite asks the user to confirm overwriting a file.
func (p *promptInput) ConfirmFileOverwrite(path string) (bool, error) {
	return p.confirm(fmt.Sprintf("Output file %s already exists. Overwrite?", path))
}

// GetEncryptionPassword prompts the user for an encryption password.
func (p *promptInput) GetEncryptionPassword() (string, error) {
	// Get the password from the user.
	password, err := p.getPassword("Enter encryption password:")
	if err != nil {
		return "", err
	}
	// Validate the password.
	if err := p.validatePassword(password); err != nil {
		return "", err
	}

	// Confirm the password.
	confirm, err := p.getPassword("Confirm password:")
	if err != nil {
		return "", err
	}
	if password != confirm {
		return "", fmt.Errorf("password mismatch")
	}
	return password, nil
}

// GetDecryptionPassword prompts the user for a decryption password.
func (p *promptInput) GetDecryptionPassword() (string, error) {
	// Get the password from the user.
	password, err := p.getPassword("Enter decryption password:")
	if err != nil {
		return "", err
	}
	// Ensure the password is not empty.
	if strings.TrimSpace(password) == "" {
		return "", fmt.Errorf("password cannot be empty")
	}
	return password, nil
}

// ConfirmFileRemoval asks the user to confirm removing a file.
func (p *promptInput) ConfirmFileRemoval(path, fileType string) (bool, options.DeleteOption, error) {
	// Ask the user to confirm the removal.
	confirm, err := p.confirm(fmt.Sprintf("Delete %s file %s?", fileType, path))
	if err != nil {
		return false, "", err
	}
	if !confirm {
		return false, "", nil
	}

	// Ask the user to choose a deletion type.
	deleteType, err := p.choose("Select delete type:", []string{
		string(options.DeleteStandard),
		string(options.DeleteSecure),
	})
	if err != nil {
		return false, "", fmt.Errorf("delete option selection failed: %w", err)
	}
	return true, options.DeleteOption(deleteType), nil
}

// GetProcessingMode prompts the user to select a processing mode.
func (p *promptInput) GetProcessingMode() (options.ProcessorMode, error) {
	// Ask the user to choose an operation.
	mode, err := p.choose("Select operation:", []string{
		string(options.ModeEncrypt),
		string(options.ModeDecrypt),
	})
	if err != nil {
		return "", fmt.Errorf("operation selection failed: %w", err)
	}
	return options.ProcessorMode(mode), nil
}

// ChooseFile prompts the user to choose a file from a list.
func (p *promptInput) ChooseFile(fileList []string) (string, error) {
	return p.choose("Select file:", fileList)
}

// getPassword prompts the user for a password.
func (p *promptInput) getPassword(message string) (string, error) {
	var password string
	err := huh.NewInput().Title(message).EchoMode(huh.EchoModePassword).Value(&password).WithTheme(huh.ThemeCatppuccin()).Run()
	if err != nil {
		return "", fmt.Errorf("password prompt failed: %w", err)
	}
	return password, nil
}

// validatePassword validates the given password.
func (p *promptInput) validatePassword(password string) error {
	// Ensure the password meets the minimum length requirement.
	if len(password) < p.passwordMinLength {
		return fmt.Errorf("password must be at least %d characters", p.passwordMinLength)
	}
	// Ensure the password is not empty.
	if strings.TrimSpace(password) == "" {
		return fmt.Errorf("password cannot be empty")
	}
	return nil
}

// confirm displays a confirmation prompt to the user.
func (p *promptInput) confirm(message string) (bool, error) {
	var confirm bool
	err := huh.NewConfirm().Title(message).Value(&confirm).WithTheme(huh.ThemeCatppuccin()).Run()
	if err != nil {
		return false, fmt.Errorf("confirmation failed: %w", err)
	}
	return confirm, nil
}

// choose displays a selection prompt to the user.
func (p *promptInput) choose(title string, optionList []string) (string, error) {
	// Ensure there are options to choose from.
	if len(optionList) == 0 {
		return "", fmt.Errorf("no options available for selection")
	}

	// Create the options for the select prompt.
	var selected string
	options := make([]huh.Option[string], len(optionList))
	for i, option := range optionList {
		options[i] = huh.NewOption(option, option)
	}

	// Run the select prompt.
	err := huh.NewSelect[string]().Title(title).Options(options...).Value(&selected).WithTheme(huh.ThemeCatppuccin()).Run()
	if err != nil {
		return "", fmt.Errorf("selection failed: %w", err)
	}
	return selected, nil
}
