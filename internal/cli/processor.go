// Package cli provides the command-line interface (CLI) implementation for the SweetByte application.
// It defines the CLI commands and their underlying processing logic for file encryption and decryption.
package cli

import (
	"fmt"

	"github.com/hambosto/sweetbyte/internal/files"
	"github.com/hambosto/sweetbyte/internal/operations"
	"github.com/hambosto/sweetbyte/internal/options"
	"github.com/hambosto/sweetbyte/internal/ui"
)

// CLIProcessor orchestrates the execution of encryption and decryption operations
// based on command-line arguments. It interacts with file management, cryptographic
// operations, and user interface components for password prompting and progress display.
type CLIProcessor struct {
	encryptor   *operations.Encryptor // Handles the core file encryption logic.
	decryptor   *operations.Decryptor // Handles the core file decryption logic.
	fileManager *files.Manager        // Manages file system operations like opening, creating, and deleting files.
	prompt      *ui.Prompt            // Provides interactive prompting for user input, such as passwords.
}

// NewCLIProcessor creates and returns a new CLIProcessor instance.
// It initializes the necessary components for performing CLI operations.
func NewCLIProcessor() *CLIProcessor {
	return &CLIProcessor{
		encryptor:   operations.NewEncryptor(), // Initialize the file encryptor.
		decryptor:   operations.NewDecryptor(), // Initialize the file decryptor.
		fileManager: files.NewManager(),        // Initialize the file manager.
		prompt:      ui.NewPrompt(),            // Initialize the UI prompt for user interaction.
	}
}

// Encrypt performs the encryption of a file specified by `inputFile` to `outputFile`.
// It handles password input (either provided directly or prompted), orchestrates the encryption
// operation, and optionally deletes the source file securely.
func (p *CLIProcessor) Encrypt(inputFile, outputFile, password string, deleteSource, secureDelete bool) error {
	if password == "" { // If no password is provided via command-line flags.
		var err error
		password, err = p.prompt.GetEncryptionPassword() // Prompt the user for the encryption password.
		if err != nil {
			return fmt.Errorf("failed to get password: %w", err) // Return error if password retrieval fails.
		}
	}

	fmt.Printf("Encrypting: %s -> %s\n", inputFile, outputFile)                      // Inform the user about the ongoing operation.
	if err := p.encryptor.EncryptFile(inputFile, outputFile, password); err != nil { // Execute the file encryption operation.
		return fmt.Errorf("failed to encrypt '%s': %w", inputFile, err) // Return error if encryption fails.
	}

	fmt.Printf("✓ File encrypted successfully: %s\n", outputFile) // Confirm successful encryption.

	if deleteSource { // Check if the source file should be deleted.
		deleteOption := options.DeleteStandard // Default to standard deletion.
		if secureDelete {                      // If secure deletion is requested.
			deleteOption = options.DeleteSecure // Set deletion option to secure.
		}

		fmt.Printf("Deleting source file: %s\n", inputFile)                   // Inform the user about source file deletion.
		if err := p.fileManager.Remove(inputFile, deleteOption); err != nil { // Perform the deletion based on the chosen option.
			return fmt.Errorf("failed to delete source file: %w", err) // Return error if deletion fails.
		}
		fmt.Printf("Source file deleted successfully\n") // Confirm successful source file deletion.
	}

	return nil // Return nil on overall success.
}

// Decrypt performs the decryption of a file specified by `inputFile` to `outputFile`.
// Similar to encryption, it handles password input, orchestrates the decryption operation,
// and optionally deletes the source encrypted file securely.
func (p *CLIProcessor) Decrypt(inputFile, outputFile, password string, deleteSource, secureDelete bool) error {
	if password == "" { // If no password is provided via command-line flags.
		var err error
		password, err = p.prompt.GetDecryptionPassword() // Prompt the user for the decryption password.
		if err != nil {
			return fmt.Errorf("failed to get password: %w", err) // Return error if password retrieval fails.
		}
	}

	fmt.Printf("Decrypting: %s -> %s\n", inputFile, outputFile)                      // Inform the user about the ongoing operation.
	if err := p.decryptor.DecryptFile(inputFile, outputFile, password); err != nil { // Execute the file decryption operation.
		return fmt.Errorf("failed to decrypt '%s': %w", inputFile, err) // Return error if decryption fails.
	}

	fmt.Printf("✓ File decrypted successfully: %s\n", outputFile) // Confirm successful decryption.
	if deleteSource {                                             // Check if the source encrypted file should be deleted.
		deleteOption := options.DeleteStandard // Default to standard deletion.
		if secureDelete {                      // If secure deletion is requested.
			deleteOption = options.DeleteSecure // Set deletion option to secure.
		}

		fmt.Printf("Deleting source file: %s\n", inputFile)                   // Inform the user about source file deletion.
		if err := p.fileManager.Remove(inputFile, deleteOption); err != nil { // Perform the deletion based on the chosen option.
			return fmt.Errorf("failed to delete source file: %w", err) // Return error if deletion fails.
		}
		fmt.Printf("Source file deleted successfully\n") // Confirm successful source file deletion.
	}

	return nil // Return nil on overall success.
}
