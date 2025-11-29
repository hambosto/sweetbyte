package ui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/huh"
	"github.com/hambosto/sweetbyte/internal/types"
)

const passwordMinLength = 8

func ConfirmFileOverwrite(path string) (bool, error) {
	var confirm bool
	if err := huh.NewConfirm().
		Title(fmt.Sprintf("Output file %s already exists. Overwrite?", path)).
		Value(&confirm).
		WithTheme(huh.ThemeCatppuccin()).
		Run(); err != nil {
		return false, fmt.Errorf("confirmation failed: %w", err)
	}
	return confirm, nil
}

func GetEncryptionPassword() (string, error) {
	var password string
	if err := huh.NewInput().
		Title("Enter encryption password:").
		EchoMode(huh.EchoModePassword).
		Value(&password).
		WithTheme(huh.ThemeCatppuccin()).
		Run(); err != nil {
		return "", fmt.Errorf("password prompt failed: %w", err)
	}

	if len(password) < passwordMinLength {
		return "", fmt.Errorf("password must be at least %d characters", passwordMinLength)
	}
	if strings.TrimSpace(password) == "" {
		return "", fmt.Errorf("password cannot be empty")
	}

	var confirm string
	if err := huh.NewInput().
		Title("Confirm password:").
		EchoMode(huh.EchoModePassword).
		Value(&confirm).
		WithTheme(huh.ThemeCatppuccin()).
		Run(); err != nil {
		return "", fmt.Errorf("password prompt failed: %w", err)
	}

	if password != confirm {
		return "", fmt.Errorf("password mismatch")
	}

	return password, nil
}

func GetDecryptionPassword() (string, error) {
	var password string
	if err := huh.NewInput().
		Title("Enter decryption password:").
		EchoMode(huh.EchoModePassword).
		Value(&password).
		WithTheme(huh.ThemeCatppuccin()).
		Run(); err != nil {
		return "", fmt.Errorf("password prompt failed: %w", err)
	}

	if strings.TrimSpace(password) == "" {
		return "", fmt.Errorf("password cannot be empty")
	}

	return password, nil
}

func ConfirmFileRemoval(path, fileType string) (bool, error) {
	var confirm bool
	if err := huh.NewConfirm().
		Title(fmt.Sprintf("Delete %s file %s?", fileType, path)).
		Value(&confirm).
		WithTheme(huh.ThemeCatppuccin()).
		Run(); err != nil {
		return false, fmt.Errorf("confirmation failed: %w", err)
	}

	if !confirm {
		return false, nil
	}

	return true, nil
}

func GetProcessingMode() (types.ProcessorMode, error) {
	options := []huh.Option[string]{
		huh.NewOption(string(types.ModeEncrypt), string(types.ModeEncrypt)),
		huh.NewOption(string(types.ModeDecrypt), string(types.ModeDecrypt)),
	}

	var selected string
	if err := huh.NewSelect[string]().
		Title("Select operation:").
		Options(options...).
		Value(&selected).
		WithTheme(huh.ThemeCatppuccin()).
		Run(); err != nil {
		return "", fmt.Errorf("operation selection failed: %w", err)
	}

	return types.ProcessorMode(selected), nil
}

func ChooseFile(fileList []string) (string, error) {
	if len(fileList) == 0 {
		return "", fmt.Errorf("no options available for selection")
	}

	options := make([]huh.Option[string], len(fileList))
	for i, file := range fileList {
		options[i] = huh.NewOption(file, file)
	}

	var selected string
	if err := huh.NewSelect[string]().
		Title("Select file:").
		Options(options...).
		Value(&selected).
		WithTheme(huh.ThemeCatppuccin()).
		Run(); err != nil {
		return "", fmt.Errorf("selection failed: %w", err)
	}

	return selected, nil
}
