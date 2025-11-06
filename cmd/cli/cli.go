package cli

import (
	"fmt"

	"sweetbyte/config"
	"sweetbyte/filemanager"
	"sweetbyte/processor"
	"sweetbyte/tui"
	"sweetbyte/types"
)

type CLI struct {
	fileManager *filemanager.FileManager
	processor   *processor.Processor
	prompt      *tui.PromptInput
}

func NewCLI() *CLI {
	fileManager := filemanager.NewFileManager(config.OverwritePasses)
	processor := processor.NewProcessor(fileManager)
	prompt := tui.NewPromptInput(config.PasswordMinLen)
	return &CLI{
		fileManager: fileManager,
		processor:   processor,
		prompt:      prompt,
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
	if err := p.processor.Encrypt(inputFile, outputFile, password); err != nil {
		return fmt.Errorf("failed to encrypt %s: %w", inputFile, err)
	}

	fmt.Printf("File encrypted successfully: %s", outputFile)
	if deleteSource {
		deleteOption := types.DeleteStandard
		if secureDelete {
			deleteOption = types.DeleteSecure
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
	if err := p.processor.Decrypt(inputFile, outputFile, password); err != nil {
		return fmt.Errorf("failed to decrypt %s: %w", inputFile, err)
	}

	fmt.Printf("✓ File decrypted successfully: %s\n", outputFile)
	if deleteSource {
		deleteOption := types.DeleteStandard
		if secureDelete {
			deleteOption = types.DeleteSecure
		}

		fmt.Printf("Deleting source file: %s\n", inputFile)
		if err := p.fileManager.Remove(inputFile, deleteOption); err != nil {
			return fmt.Errorf("failed to delete source file: %w", err)
		}
		fmt.Printf("Source file deleted successfully\n")
	}

	return nil
}
