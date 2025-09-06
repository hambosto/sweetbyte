// Package ui provides components for the user interface of the SweetByte application.
package ui

import (
	"fmt"
	"strings"

	"github.com/AlecAivazis/survey/v2"
	"github.com/hambosto/sweetbyte/internal/files"
	"github.com/hambosto/sweetbyte/internal/options"
	"github.com/hambosto/sweetbyte/internal/utils"
)

// PasswordRequest represents a password prompt request
type PasswordRequest struct {
	Message    string
	Confirm    bool
	MinLength  int
	Validation func(string) error
}

// SelectionRequest represents a selection prompt request
type SelectionRequest struct {
	Message  string
	Options  []string
	HelpText string
	PageSize int
}

// ConfirmationRequest represents a confirmation prompt request
type ConfirmationRequest struct {
	Message  string
	Default  bool
	HelpText string
}

// FileDisplayOptions controls how file information is displayed
type FileDisplayOptions struct {
	ShowIndex    bool
	ShowSize     bool
	ShowStatus   bool
	Compact      bool
	ColorEnabled bool
}

// Prompt defines the interface for interacting with the user via prompts.
type Prompt interface {
	ConfirmFileOverwrite(path string) (bool, error)
	GetEncryptionPassword() (string, error)
	GetDecryptionPassword() (string, error)
	ConfirmFileRemoval(path, fileType string) (bool, options.DeleteOption, error)
	GetProcessingMode() (options.ProcessorMode, error)
	ChooseFile(fileList []string) (string, error)
	ShowFileInfo(fileList []files.FileInfo)
	ShowProcessingInfo(mode options.ProcessorMode, filePath string)
}

// prompt provides functions for interacting with the user via prompts.
type prompt struct {
	PasswordMinLength int
}

// NewPrompt creates a new Prompt instance
func NewPrompt(passwordMinLength int) Prompt {
	return &prompt{PasswordMinLength: passwordMinLength}
}

// ConfirmFileOverwrite asks the user to confirm overwriting a file.
func (p *prompt) ConfirmFileOverwrite(path string) (bool, error) {
	req := &ConfirmationRequest{
		Message:  fmt.Sprintf("Output file %s already exists. Overwrite?", path),
		Default:  false,
		HelpText: "This action cannot be undone",
	}
	return p.confirm(req)
}

// GetEncryptionPassword prompts the user for an encryption password and confirms it.
func (p *prompt) GetEncryptionPassword() (string, error) {
	req := &PasswordRequest{
		Message:   "Enter encryption password:",
		Confirm:   true,
		MinLength: p.PasswordMinLength,
		Validation: func(password string) error {
			if len(password) < p.PasswordMinLength {
				return fmt.Errorf("password must be at least %d characters", p.PasswordMinLength)
			}
			if strings.TrimSpace(password) == "" {
				return fmt.Errorf("password cannot be empty")
			}
			return nil
		},
	}
	return p.getPasswordWithRequest(req)
}

// GetDecryptionPassword prompts the user for a decryption password.
func (p *prompt) GetDecryptionPassword() (string, error) {
	req := &PasswordRequest{
		Message:   "Enter decryption password:",
		Confirm:   false,
		MinLength: 1,
		Validation: func(password string) error {
			if strings.TrimSpace(password) == "" {
				return fmt.Errorf("password cannot be empty")
			}
			return nil
		},
	}
	return p.getPasswordWithRequest(req)
}

// ConfirmFileRemoval asks the user to confirm removing a file and the deletion type.
func (p *prompt) ConfirmFileRemoval(path, fileType string) (bool, options.DeleteOption, error) {
	// Confirm the removal action
	confirmReq := &ConfirmationRequest{
		Message:  fmt.Sprintf("Delete %s file %s", fileType, path),
		Default:  false,
		HelpText: "Choose deletion type after confirmation",
	}

	confirmed, err := p.confirm(confirmReq)
	if err != nil {
		return false, "", fmt.Errorf("failed to confirm file removal: %w", err)
	}

	// If not confirmed, return early
	if !confirmed {
		return false, "", nil
	}

	// Select the deletion type
	deleteType, err := p.selectDeleteOption()
	if err != nil {
		return false, "", fmt.Errorf("failed to select delete option: %w", err)
	}

	return true, deleteType, nil
}

// GetProcessingMode prompts the user to select a processing mode (encrypt or decrypt).
func (p *prompt) GetProcessingMode() (options.ProcessorMode, error) {
	req := &SelectionRequest{
		Message:  "Select Operation:",
		Options:  []string{string(options.ModeEncrypt), string(options.ModeDecrypt)},
		HelpText: "Choose whether to encrypt or decrypt files",
		PageSize: 10,
	}

	selected, err := p.selectFromRequest(req)
	if err != nil {
		return "", fmt.Errorf("operation selection failed: %w", err)
	}

	return options.ProcessorMode(selected), nil
}

// ChooseFile prompts the user to choose a file from a list of files.
func (p *prompt) ChooseFile(fileList []string) (string, error) {
	if len(fileList) == 0 {
		return "", fmt.Errorf("no files available for selection")
	}

	req := &SelectionRequest{
		Message:  "Select file:",
		Options:  fileList,
		HelpText: "Use arrow keys to navigate, Enter to select",
		PageSize: min(len(fileList), 15),
	}

	selected, err := p.selectFromRequest(req)
	if err != nil {
		return "", fmt.Errorf("file selection failed: %w", err)
	}

	return selected, nil
}

// ShowFileInfo displays information about a list of files.
func (p *prompt) ShowFileInfo(fileList []files.FileInfo) {
	if len(fileList) == 0 {
		fmt.Println("No files found.")
		return
	}

	opts := &FileDisplayOptions{
		ShowIndex:    true,
		ShowSize:     true,
		ShowStatus:   true,
		Compact:      false,
		ColorEnabled: true,
	}

	fmt.Println()
	fmt.Printf("Found %d file(s):", len(fileList))
	fmt.Println()

	for i, file := range fileList {
		p.displayFileInfo(i+1, file, opts)
	}
	fmt.Println()
}

// ShowProcessingInfo displays information about the current processing operation.
func (p *prompt) ShowProcessingInfo(mode options.ProcessorMode, filePath string) {
	operation := "Encrypting"
	if mode == options.ModeDecrypt {
		operation = "Decrypting"
	}

	fmt.Println()
	fmt.Printf("%s file: %s", operation, filePath)
	fmt.Println()
}

// getPasswordWithRequest handles password prompts with validation and confirmation
func (p *prompt) getPasswordWithRequest(req *PasswordRequest) (string, error) {
	// Get the initial password
	password, err := p.getPassword(req.Message)
	if err != nil {
		return "", fmt.Errorf("failed to get password: %w", err)
	}

	// Validate the password
	if req.Validation != nil {
		if err := req.Validation(password); err != nil {
			return "", fmt.Errorf("failed to validate password: %v", err)
		}
	}

	// Confirm password if required
	if req.Confirm {
		confirm, err := p.getPassword("Confirm password:")
		if err != nil {
			return "", fmt.Errorf("failed to confirm password: %w", err)
		}

		if password != confirm {
			return "", fmt.Errorf("password mismatch. Please try again")
		}
	}
	return password, nil
}

// getPassword prompts the user for a password with a given message
func (p *prompt) getPassword(message string) (string, error) {
	var password string
	prompt := &survey.Password{
		Message: message,
	}

	if err := survey.AskOne(prompt, &password); err != nil {
		return "", fmt.Errorf("prompt failed: %w", err)
	}

	return password, nil
}

// confirm handles confirmation prompts
func (p *prompt) confirm(req *ConfirmationRequest) (bool, error) {
	var result bool
	prompt := &survey.Confirm{
		Message: req.Message,
		Default: req.Default,
		Help:    req.HelpText,
	}

	if err := survey.AskOne(prompt, &result); err != nil {
		return false, fmt.Errorf("prompt failed: %w", err)
	}

	return result, nil
}

// selectFromRequest handles selection prompts with options
func (p *prompt) selectFromRequest(req *SelectionRequest) (string, error) {
	var selected string
	prompt := &survey.Select{
		Message:  req.Message,
		Options:  req.Options,
		Help:     req.HelpText,
		PageSize: req.PageSize,
	}

	if err := survey.AskOne(prompt, &selected); err != nil {
		return "", fmt.Errorf("prompt failed: %w", err)
	}

	return selected, nil
}

// selectDeleteOption prompts the user to select a deletion option
func (p *prompt) selectDeleteOption() (options.DeleteOption, error) {
	req := &SelectionRequest{
		Message: "Select delete type:",
		Options: []string{
			string(options.DeleteStandard),
			string(options.DeleteSecure),
		},
		HelpText: "Standard: normal deletion, Secure: overwrite data before deletion",
		PageSize: 10,
	}

	selected, err := p.selectFromRequest(req)
	if err != nil {
		return "", err
	}

	return options.DeleteOption(selected), nil
}

// displayFileInfo formats and displays individual file information
func (p *prompt) displayFileInfo(index int, file files.FileInfo, opts *FileDisplayOptions) {
	var parts []string

	if opts.ShowIndex {
		parts = append(parts, fmt.Sprintf("%d.", index))
	}

	parts = append(parts, file.Path)

	var details []string
	if opts.ShowSize {
		details = append(details, utils.FormatBytes(file.Size))
	}

	if opts.ShowStatus {
		status := "unencrypted"
		if file.IsEncrypted {
			status = "encrypted"
		}
		details = append(details, status)
	}

	if len(details) > 0 {
		if opts.Compact {
			parts = append(parts, fmt.Sprintf("(%s)", strings.Join(details, ", ")))
		} else {
			parts = append(parts, fmt.Sprintf("(%s)", strings.Join(details, ", ")))
		}
	}

	fmt.Println(strings.Join(parts, " "))
}
