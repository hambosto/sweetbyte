// Package cli provides the command-line interface for the application.
package cli

import (
	"fmt"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/files"
	"github.com/hambosto/sweetbyte/internal/operations"
	"github.com/hambosto/sweetbyte/internal/options"
	"github.com/hambosto/sweetbyte/internal/ui"
)

// CLI handles the application's command-line interface logic.
type CLI struct {
	fileManager    files.FileManager
	fileOperations operations.FileOperations
	prompt         ui.PromptInput
}

// NewCLI creates a new CLI instance with its dependencies.
func NewCLI() *CLI {
	// Initialize dependencies.
	fileManager := files.NewFileManager(config.OverwritePasses)
	fileOperations := operations.NewFileOperations(fileManager)
	prompt := ui.NewPromptInput(config.PasswordMinLen)
	return &CLI{
		fileManager:    fileManager,
		fileOperations: fileOperations,
		prompt:         prompt,
	}
}

// Encrypt handles the file encryption process.
func (p *CLI) Encrypt(inputFile, outputFile, password string, deleteSource, secureDelete bool) error {
	// If no password is provided, prompt the user for one.
	if len(password) == 0 {
		var err error
		password, err = p.prompt.GetEncryptionPassword()
		if err != nil {
			return fmt.Errorf("failed to get password: %w", err)
		}
	}

	// Perform the encryption.
	fmt.Printf("Encrypting: %s -> %s\n", inputFile, outputFile)
	if err := p.fileOperations.Encrypt(inputFile, outputFile, password); err != nil {
		return fmt.Errorf("failed to encrypt %s: %w", inputFile, err)
	}

	// Optionally, delete the source file.
	fmt.Printf("File encrypted successfully: %s", outputFile)
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

// Decrypt handles the file decryption process.
func (p *CLI) Decrypt(inputFile, outputFile, password string, deleteSource, secureDelete bool) error {
	// If no password is provided, prompt the user for one.
	if len(password) == 0 {
		var err error
		password, err = p.prompt.GetDecryptionPassword()
		if err != nil {
			return fmt.Errorf("failed to get password: %w", err)
		}
	}

	// Perform the decryption.
	fmt.Printf("Decrypting: %s -> %s\n", inputFile, outputFile)
	if err := p.fileOperations.Decrypt(inputFile, outputFile, password); err != nil {
		return fmt.Errorf("failed to decrypt %s: %w", inputFile, err)
	}

	// Optionally, delete the source file.
	fmt.Printf("✓ File decrypted successfully: %s\n", outputFile)
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
