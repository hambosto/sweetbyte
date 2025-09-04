// Package cli provides the command-line interface functionality for SweetByte.
package cli

import (
	"fmt"

	"github.com/hambosto/sweetbyte/internal/files"
	"github.com/hambosto/sweetbyte/internal/operations"
	"github.com/hambosto/sweetbyte/internal/options"
	"github.com/hambosto/sweetbyte/internal/ui"
)

// CLIProcessor handles the command-line interface operations.
type CLIProcessor struct {
	encryptor   *operations.Encryptor
	decryptor   *operations.Decryptor
	fileManager *files.FileManager
	prompt      *ui.Prompt
}

// NewCLIProcessor creates a new CLIProcessor.
func NewCLIProcessor() *CLIProcessor {
	fileManager := files.NewFileManager(3, 4096, true)
	return &CLIProcessor{
		encryptor:   operations.NewEncryptor(fileManager),
		decryptor:   operations.NewDecryptor(fileManager),
		fileManager: fileManager,
		prompt:      ui.NewPrompt(8),
	}
}

// Encrypt encrypts a file using the command-line interface.
func (p *CLIProcessor) Encrypt(inputFile, outputFile, password string, deleteSource, secureDelete bool) error {
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
	if err := p.encryptor.EncryptFile(inputFile, outputFile, password); err != nil {
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
func (p *CLIProcessor) Decrypt(inputFile, outputFile, password string, deleteSource, secureDelete bool) error {
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
	if err := p.decryptor.DecryptFile(inputFile, outputFile, password); err != nil {
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
