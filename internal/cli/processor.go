package cli

import (
	"fmt"

	"github.com/hambosto/sweetbyte/internal/files"
	"github.com/hambosto/sweetbyte/internal/operations"
	"github.com/hambosto/sweetbyte/internal/options"
	"github.com/hambosto/sweetbyte/internal/ui"
)

// CLIProcessor orchestrates the encryption and decryption processes based on CLI input.
// It interacts with the core operations, file management, and UI components.
type CLIProcessor struct {
	encryptor   *operations.Encryptor
	decryptor   *operations.Decryptor
	fileManager *files.Manager
	prompt      *ui.Prompt
}

// NewCLIProcessor creates a new CLIProcessor and initializes its dependencies.
func NewCLIProcessor() *CLIProcessor {
	return &CLIProcessor{
		encryptor:   operations.NewEncryptor(),
		decryptor:   operations.NewDecryptor(),
		fileManager: files.NewManager(),
		prompt:      ui.NewPrompt(),
	}
}

// Encrypt handles the file encryption process based on the provided CLI flags.
// It prompts for a password if one is not supplied, runs the encryption,
// and handles the optional deletion of the source file.
func (p *CLIProcessor) Encrypt(inputFile, outputFile, password string, deleteSource, secureDelete bool) error {
	// Get password if not provided
	if password == "" {
		var err error
		password, err = p.prompt.GetEncryptionPassword()
		if err != nil {
			return fmt.Errorf("failed to get password: %w", err)
		}
	}

	fmt.Printf("Encrypting: %s -> %s\n", inputFile, outputFile)

	// Perform encryption
	if err := p.encryptor.EncryptFile(inputFile, outputFile, password); err != nil {
		return fmt.Errorf("failed to encrypt '%s': %w", inputFile, err)
	}

	fmt.Printf("✓ File encrypted successfully: %s\n", outputFile)

	// Handle source file deletion if requested
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

// Decrypt handles the file decryption process based on the provided CLI flags.
// It prompts for a password if one is not supplied, runs the decryption,
// and handles the optional deletion of the source file.
func (p *CLIProcessor) Decrypt(inputFile, outputFile, password string, deleteSource, secureDelete bool) error {
	// Get password if not provided
	if password == "" {
		var err error
		password, err = p.prompt.GetDecryptionPassword()
		if err != nil {
			return fmt.Errorf("failed to get password: %w", err)
		}
	}

	fmt.Printf("Decrypting: %s -> %s\n", inputFile, outputFile)

	if err := p.decryptor.DecryptFile(inputFile, outputFile, password); err != nil {
		return fmt.Errorf("failed to decrypt '%s': %w", inputFile, err)
	}

	fmt.Printf("✓ File decrypted successfully: %s\n", outputFile)

	// Handle source file deletion if requested
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
