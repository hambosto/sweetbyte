package tui

import (
	"fmt"
	"strings"

	"sweetbyte/options"

	"github.com/charmbracelet/huh"
)

type PromptInput interface {
	ConfirmFileOverwrite(path string) (bool, error)
	GetEncryptionPassword() (string, error)
	GetDecryptionPassword() (string, error)
	ConfirmFileRemoval(path, fileType string) (bool, options.DeleteOption, error)
	GetProcessingMode() (options.ProcessorMode, error)
	ChooseFile(fileList []string) (string, error)
}

type promptInput struct {
	passwordMinLength int
}

func NewPromptInput(passwordMinLength int) PromptInput {
	return &promptInput{passwordMinLength: passwordMinLength}
}

func (p *promptInput) ConfirmFileOverwrite(path string) (bool, error) {
	return p.confirm(fmt.Sprintf("Output file %s already exists. Overwrite?", path))
}

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

func (p *promptInput) ConfirmFileRemoval(path, fileType string) (bool, options.DeleteOption, error) {
	confirm, err := p.confirm(fmt.Sprintf("Delete %s file %s?", fileType, path))
	if err != nil {
		return false, "", err
	}
	if !confirm {
		return false, "", nil
	}

	deleteType, err := p.choose("Select delete type:", []string{
		string(options.DeleteStandard),
		string(options.DeleteSecure),
	})
	if err != nil {
		return false, "", fmt.Errorf("delete option selection failed: %w", err)
	}
	return true, options.DeleteOption(deleteType), nil
}

func (p *promptInput) GetProcessingMode() (options.ProcessorMode, error) {
	mode, err := p.choose("Select operation:", []string{
		string(options.ModeEncrypt),
		string(options.ModeDecrypt),
	})
	if err != nil {
		return "", fmt.Errorf("operation selection failed: %w", err)
	}
	return options.ProcessorMode(mode), nil
}

func (p *promptInput) ChooseFile(fileList []string) (string, error) {
	return p.choose("Select file:", fileList)
}

func (p *promptInput) getPassword(message string) (string, error) {
	var password string
	if err := huh.NewInput().Title(message).EchoMode(huh.EchoModePassword).Value(&password).WithTheme(huh.ThemeCatppuccin()).Run(); err != nil {
		return "", fmt.Errorf("password prompt failed: %w", err)
	}
	return password, nil
}

func (p *promptInput) validatePassword(password string) error {
	if len(password) < p.passwordMinLength {
		return fmt.Errorf("password must be at least %d characters", p.passwordMinLength)
	}

	if strings.TrimSpace(password) == "" {
		return fmt.Errorf("password cannot be empty")
	}
	return nil
}

func (p *promptInput) confirm(message string) (bool, error) {
	var confirm bool
	if err := huh.NewConfirm().Title(message).Value(&confirm).WithTheme(huh.ThemeCatppuccin()).Run(); err != nil {
		return false, fmt.Errorf("confirmation failed: %w", err)
	}
	return confirm, nil
}

func (p *promptInput) choose(title string, optionList []string) (string, error) {
	if len(optionList) == 0 {
		return "", fmt.Errorf("no options available for selection")
	}

	options := make([]huh.Option[string], len(optionList))
	for i, option := range optionList {
		options[i] = huh.NewOption(option, option)
	}

	var selected string
	if err := huh.NewSelect[string]().Title(title).Options(options...).Value(&selected).WithTheme(huh.ThemeCatppuccin()).Run(); err != nil {
		return "", fmt.Errorf("selection failed: %w", err)
	}

	return selected, nil
}
