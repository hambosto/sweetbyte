package cli

import (
	"fmt"

	"github.com/hambosto/sweetbyte/internal/files"
	"github.com/hambosto/sweetbyte/internal/operations"
	"github.com/hambosto/sweetbyte/internal/options"
	"github.com/hambosto/sweetbyte/internal/ui"
)

type CLIProcessor struct {
	encryptor	*operations.Encryptor
	decryptor	*operations.Decryptor
	fileManager	*files.Manager
	prompt		*ui.Prompt
}

func NewCLIProcessor() *CLIProcessor {
	return &CLIProcessor{
		encryptor:	operations.NewEncryptor(),
		decryptor:	operations.NewDecryptor(),
		fileManager:	files.NewManager(),
		prompt:		ui.NewPrompt(),
	}
}

func (p *CLIProcessor) Encrypt(inputFile, outputFile, password string, deleteSource, secureDelete bool) error {
	if password == "" {
		var err error
		password, err = p.prompt.GetEncryptionPassword()
		if err != nil {
			return fmt.Errorf("failed to get password: %w", err)
		}
	}

	fmt.Printf("Encrypting: %s -> %s\n", inputFile, outputFile)

	if err := p.encryptor.EncryptFile(inputFile, outputFile, password); err != nil {
		return fmt.Errorf("failed to encrypt '%s': %w", inputFile, err)
	}

	fmt.Printf("✓ File encrypted successfully: %s\n", outputFile)

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

func (p *CLIProcessor) Decrypt(inputFile, outputFile, password string, deleteSource, secureDelete bool) error {
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
