package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/hambosto/sweetbyte/types"
)

type PromptInput struct {
	passwordMinLength int
}

func NewPromptInput(passwordMinLength int) *PromptInput {
	return &PromptInput{passwordMinLength: passwordMinLength}
}

func (p *PromptInput) ConfirmFileOverwrite(path string) (bool, error) {
	return p.confirm(fmt.Sprintf("Output file %s already exists. Overwrite?", path))
}

func (p *PromptInput) GetEncryptionPassword() (string, error) {
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

func (p *PromptInput) GetDecryptionPassword() (string, error) {
	password, err := p.getPassword("Enter decryption password:")
	if err != nil {
		return "", err
	}

	if strings.TrimSpace(password) == "" {
		return "", fmt.Errorf("password cannot be empty")
	}
	return password, nil
}

func (p *PromptInput) ConfirmFileRemoval(path, fileType string) (bool, error) {
	confirm, err := p.confirm(fmt.Sprintf("Delete %s file %s?", fileType, path))
	if err != nil {
		return false, err
	}
	if !confirm {
		return false, nil
	}

	return true, nil
}

func (p *PromptInput) GetProcessingMode() (types.ProcessorMode, error) {
	mode, err := p.choose("Select operation:", []string{
		string(types.ModeEncrypt),
		string(types.ModeDecrypt),
	})
	if err != nil {
		return "", fmt.Errorf("operation selection failed: %w", err)
	}
	return types.ProcessorMode(mode), nil
}

func (p *PromptInput) ChooseFile(fileList []string) (string, error) {
	return p.choose("Select file:", fileList)
}

func (p *PromptInput) getPassword(message string) (string, error) {
	var password string
	if err := huh.NewInput().Title(message).EchoMode(huh.EchoModePassword).Value(&password).WithTheme(huh.ThemeCatppuccin()).Run(); err != nil {
		return "", fmt.Errorf("password prompt failed: %w", err)
	}
	return password, nil
}

func (p *PromptInput) validatePassword(password string) error {
	if len(password) < p.passwordMinLength {
		return fmt.Errorf("password must be at least %d characters", p.passwordMinLength)
	}

	if strings.TrimSpace(password) == "" {
		return fmt.Errorf("password cannot be empty")
	}
	return nil
}

func (p *PromptInput) confirm(message string) (bool, error) {
	var confirm bool
	if err := huh.NewConfirm().Title(message).Value(&confirm).WithTheme(huh.ThemeCatppuccin()).Run(); err != nil {
		return false, fmt.Errorf("confirmation failed: %w", err)
	}
	return confirm, nil
}

func (p *PromptInput) choose(title string, optionList []string) (string, error) {
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
