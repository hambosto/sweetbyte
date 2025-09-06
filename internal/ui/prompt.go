// Package ui provides user interaction components for the SweetByte application.
// It defines a prompt-based interface for confirming actions, selecting modes,
// handling file operations, and securely gathering passwords.
package ui

import (
	"fmt"
	"strings"

	"github.com/cqroot/prompt"
	"github.com/cqroot/prompt/input"
	"github.com/hambosto/sweetbyte/internal/options"
)

// confirmMap maps string responses to boolean values.
var confirmMap = map[string]bool{
	"Yes": true,
	"No":  false,
}

// PromptInput defines the interface for user interactions via prompts.
// This abstraction allows SweetByte to swap prompt libraries or mock user input in tests.
type PromptInput interface {
	ConfirmFileOverwrite(path string) (bool, error)
	GetEncryptionPassword() (string, error)
	GetDecryptionPassword() (string, error)
	ConfirmFileRemoval(path, fileType string) (bool, options.DeleteOption, error)
	GetProcessingMode() (options.ProcessorMode, error)
	ChooseFile(fileList []string) (string, error)
}

// promptInput is the default implementation of PromptInput.
type promptInput struct {
	passwordMinLength int
}

// NewPromptInput returns a PromptInput with a minimum password length requirement.
func NewPromptInput(passwordMinLength int) PromptInput {
	return &promptInput{passwordMinLength: passwordMinLength}
}

// ConfirmFileOverwrite asks the user to confirm overwriting an existing file.
func (p *promptInput) ConfirmFileOverwrite(path string) (bool, error) {
	return p.confirm(fmt.Sprintf("Output file %s already exists. Overwrite?", path))
}

// GetEncryptionPassword prompts for a password, validates it, and requires confirmation.
func (p *promptInput) GetEncryptionPassword() (string, error) {
	password, err := p.getPassword("Enter encryption password:")
	if err != nil {
		return "", err
	}
	if err := p.validatePassword(password); err != nil {
		return "", err
	}

	confirm, err := p.getPassword("Confirm password:")
	if err != nil {
		return "", err
	}
	if password != confirm {
		return "", fmt.Errorf("password mismatch")
	}
	return password, nil
}

// GetDecryptionPassword prompts for a password used in decryption.
func (p *promptInput) GetDecryptionPassword() (string, error) {
	password, err := p.getPassword("Enter decryption password:")
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(password) == "" {
		return "", fmt.Errorf("password cannot be empty")
	}
	return password, nil
}

// ConfirmFileRemoval asks the user to confirm file deletion and choose a deletion type.
func (p *promptInput) ConfirmFileRemoval(path, fileType string) (bool, options.DeleteOption, error) {
	confirm, err := p.confirm(fmt.Sprintf("Delete %s file %s?", fileType, path))
	if err != nil {
		return false, "", err
	}
	if !confirm {
		return false, "", nil
	}

	choice, err := p.choose("Select delete type:", []string{
		string(options.DeleteStandard),
		string(options.DeleteSecure),
	})
	if err != nil {
		return false, "", fmt.Errorf("delete option selection failed: %w", err)
	}
	return true, options.DeleteOption(choice), nil
}

// GetProcessingMode asks the user to select encryption or decryption.
func (p *promptInput) GetProcessingMode() (options.ProcessorMode, error) {
	choice, err := p.choose("Select operation:", []string{
		string(options.ModeEncrypt),
		string(options.ModeDecrypt),
	})
	if err != nil {
		return "", fmt.Errorf("operation selection failed: %w", err)
	}
	return options.ProcessorMode(choice), nil
}

// ChooseFile asks the user to pick a file from a list.
func (p *promptInput) ChooseFile(fileList []string) (string, error) {
	if len(fileList) == 0 {
		return "", fmt.Errorf("no files available for selection")
	}
	return p.choose("Select file:", fileList)
}

// getPassword securely prompts for a password (hidden input).
func (p *promptInput) getPassword(message string) (string, error) {
	pass, err := prompt.New().Ask(message).Input("", input.WithEchoMode(input.EchoPassword))
	if err != nil {
		return "", fmt.Errorf("password prompt failed: %w", err)
	}
	return pass, nil
}

// validatePassword checks minimum length and non-empty requirements.
func (p *promptInput) validatePassword(password string) error {
	if len(password) < p.passwordMinLength {
		return fmt.Errorf("password must be at least %d characters", p.passwordMinLength)
	}
	if strings.TrimSpace(password) == "" {
		return fmt.Errorf("password cannot be empty")
	}
	return nil
}

// askYesNo presents a Yes/No choice and returns the boolean value.
func (p *promptInput) confirm(message string) (bool, error) {
	choice, err := p.choose(message, []string{"Yes", "No"})
	if err != nil {
		return false, fmt.Errorf("confirmation failed: %w", err)
	}
	return confirmMap[choice], nil
}

// choose presents a list of options and returns the selected value.
func (p *promptInput) choose(message string, options []string) (string, error) {
	choice, err := prompt.New().Ask(message).Choose(options)
	if err != nil {
		return "", err
	}
	return choice, nil
}
