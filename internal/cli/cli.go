// Package cli provides the command-line interface functionality for SweetByte.
package cli

import (
	"fmt"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/files"
	"github.com/hambosto/sweetbyte/internal/operations"
	"github.com/hambosto/sweetbyte/internal/options"
	"github.com/hambosto/sweetbyte/internal/ui"
)

// CLI handles the command-line interface operations.
type CLI struct {
	fileManager    files.FileManager
	fileOperations operations.FileOperations
	prompt         ui.Prompt
}

// NewCLI creates a new CLI.
func NewCLI() *CLI {
	fileManager := files.NewFileManager(config.OverwritePasses)
	fileOperations := operations.NewFileOperations(fileManager)
	prompt := ui.NewPrompt(config.PasswordMinLen)
	return &CLI{
		fileManager:    fileManager,
		fileOperations: fileOperations,
		prompt:         prompt,
	}
}

// Encrypt encrypts a file using the command-line interface.
func (p *CLI) Encrypt(inputFile, outputFile, password string, deleteSource, secureDelete bool) error {
	// If no password is provided, prompt the user for one.
	if len(password) == 0 {
		var err error
		password, err = p.prompt.GetEncryptionPassword()
		if err != nil {
			return fmt.Errorf("failed to get password: %w", err)
		}
	}

	// Encrypt the file.
	fmt.Printf("Encrypting: %s -> %s\n", inputFile, outputFile)
	if err := p.fileOperations.Encrypt(inputFile, outputFile, password); err != nil {
		return fmt.Errorf("failed to encrypt '%s': %w", inputFile, err)
	}

	fmt.Printf("✓ File encrypted successfully: %s\n", outputFile)

	// If requested, delete the source file.
	if deleteSource {
		deleteOption := options.DeleteStandard
		if secureDelete {
			deleteOption = options.DeleteSecure
		}

		fmt.Printf("Deleting source file: %s\n", inputFile)
		if err := p.fileManager.Remove(inputFile, deleteOption); err != nil {
			return fmt.Errorf("failed to delete source file: %w", err)
		}
		fmt.Printf("Source file deleted successfully\n")
	}

	return nil
}

// Decrypt decrypts a file using the command-line interface.
func (p *CLI) Decrypt(inputFile, outputFile, password string, deleteSource, secureDelete bool) error {
	// If no password is provided, prompt the user for one.
	if len(password) == 0 {
		var err error
		password, err = p.prompt.GetDecryptionPassword()
		if err != nil {
			return fmt.Errorf("failed to get password: %w", err)
		}
	}

	// Decrypt the file.
	fmt.Printf("Decrypting: %s -> %s\n", inputFile, outputFile)
	if err := p.fileOperations.Decrypt(inputFile, outputFile, password); err != nil {
		return fmt.Errorf("failed to decrypt '%s': %w", inputFile, err)
	}

	fmt.Printf("✓ File decrypted successfully: %s\n", outputFile)
	// If requested, delete the source file.
	if deleteSource {
		deleteOption := options.DeleteStandard
		if secureDelete {
			deleteOption = options.DeleteSecure
		}

		fmt.Printf("Deleting source file: %s\n", inputFile)
		if err := p.fileManager.Remove(inputFile, deleteOption); err != nil {
			return fmt.Errorf("failed to delete source file: %w", err)
		}
		fmt.Printf("Source file deleted successfully\n")
	}

	return nil
}
