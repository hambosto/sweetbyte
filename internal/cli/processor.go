package cli

import (
	"fmt"

	"github.com/hambosto/sweetbyte/internal/files"
	"github.com/hambosto/sweetbyte/internal/operations"
	"github.com/hambosto/sweetbyte/internal/types"
	"github.com/hambosto/sweetbyte/internal/ui"
)

// CLIProcessor handles CLI-based encryption and decryption operations
type CLIProcessor struct {
	encryptor   *operations.Encryptor
	decryptor   *operations.Decryptor
	fileManager *files.Manager
	prompt      *ui.Prompt
}

// NewCLIProcessor creates a new CLI processor instance
func NewCLIProcessor() *CLIProcessor {
	return &CLIProcessor{
		encryptor:   operations.NewEncryptor(),
		decryptor:   operations.NewDecryptor(),
		fileManager: files.NewManager(),
		prompt:      ui.NewPrompt(),
	}
}

// Encrypt encrypts a file using CLI parameters
func (p *CLIProcessor) Encrypt(inputFile, outputFile, password string, deleteSource, secureDelete bool) error {
	// Get password if not provided
	if password == "" {
		var err error
		password, err = p.prompt.GetEncryptionPassword()
		if err != nil {
			return err
		}
	}

	fmt.Printf("Encrypting: %s -> %s\n", inputFile, outputFile)

	// Perform encryption
	if err := p.encryptor.EncryptFile(inputFile, outputFile, password); err != nil {
		return fmt.Errorf("encryption failed: %w", err)
	}

	// Handle source file deletion if requested
	if deleteSource {
		deleteOption := types.DeleteStandard
		if secureDelete {
			deleteOption = types.DeleteSecure
		}

		fmt.Printf("Deleting source file: %s\n", inputFile)
		if err := p.fileManager.Remove(inputFile, deleteOption); err != nil {
			fmt.Printf("Warning: Failed to delete source file: %v\n", err)
		} else {
			fmt.Printf("Source file deleted successfully\n")
		}
	}

	fmt.Printf("✓ File encrypted successfully: %s\n", outputFile)
	return nil
}

// Decrypt decrypts a file using CLI parameters
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
		return fmt.Errorf("decryption failed: %w", err)
	}

	// Handle source file deletion if requested
	if deleteSource {
		deleteOption := types.DeleteStandard
		if secureDelete {
			deleteOption = types.DeleteSecure
		}

		fmt.Printf("Deleting source file: %s\n", inputFile)
		if err := p.fileManager.Remove(inputFile, deleteOption); err != nil {
			fmt.Printf("Warning: Failed to delete source file: %v\n", err)
		} else {
			fmt.Printf("Source file deleted successfully\n")
		}
	}

	fmt.Printf("✓ File decrypted successfully: %s\n", outputFile)
	return nil
}
