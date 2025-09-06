package cli

import (
	"fmt"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/files"
	"github.com/hambosto/sweetbyte/internal/operations"
	"github.com/hambosto/sweetbyte/internal/options"
	"github.com/hambosto/sweetbyte/internal/ui"
)

type CLI struct {
	fileManager	files.FileManager
	fileOperations	operations.FileOperations
	prompt		ui.PromptInput
}

func NewCLI() *CLI {
	fileManager := files.NewFileManager(config.OverwritePasses)
	fileOperations := operations.NewFileOperations(fileManager)
	prompt := ui.NewPromptInput(config.PasswordMinLen)
	return &CLI{
		fileManager:	fileManager,
		fileOperations:	fileOperations,
		prompt:		prompt,
	}
}

func (p *CLI) Encrypt(inputFile, outputFile, password string, deleteSource, secureDelete bool) error {
	if len(password) == 0 {
		var err error
		password, err = p.prompt.GetEncryptionPassword()
		if err != nil {
			return fmt.Errorf("failed to get password: %w", err)
		}
	}

	fmt.Printf("Encrypting: %s -> %s\n", inputFile, outputFile)
	if err := p.fileOperations.Encrypt(inputFile, outputFile, password); err != nil {
		return fmt.Errorf("failed to encrypt %s: %w", inputFile, err)
	}

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

func (p *CLI) Decrypt(inputFile, outputFile, password string, deleteSource, secureDelete bool) error {
	if len(password) == 0 {
		var err error
		password, err = p.prompt.GetDecryptionPassword()
		if err != nil {
			return fmt.Errorf("failed to get password: %w", err)
		}
	}

	fmt.Printf("Decrypting: %s -> %s\n", inputFile, outputFile)
	if err := p.fileOperations.Decrypt(inputFile, outputFile, password); err != nil {
		return fmt.Errorf("failed to decrypt %s: %w", inputFile, err)
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
