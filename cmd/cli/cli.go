package cli

import (
	"fmt"

	"github.com/hambosto/sweetbyte/filemanager"
	"github.com/hambosto/sweetbyte/processor"
	"github.com/hambosto/sweetbyte/ui"
)

type CLI struct {
	fileManager *filemanager.FileManager
	processor   *processor.Processor
	prompt      *ui.PromptInput
}

func NewCLI() *CLI {
	fileManager := filemanager.NewFileManager(filemanager.OverwritePasses)
	processor := processor.NewProcessor(fileManager)
	prompt := ui.NewPromptInput(filemanager.PasswordMinLen)
	return &CLI{
		fileManager: fileManager,
		processor:   processor,
		prompt:      prompt,
	}
}

func (p *CLI) Encrypt(inputFile, outputFile, password string, deleteSource bool) error {
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
		fmt.Printf("Deleting source file: %s\n", inputFile)
		if err := p.fileManager.Remove(inputFile); err != nil {
			return fmt.Errorf("failed to delete source file: %w", err)
		}
		fmt.Printf("Source file deleted successfully\n")
	}

	return nil
}

func (p *CLI) Decrypt(inputFile, outputFile, password string, deleteSource bool) error {
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
		fmt.Printf("Deleting source file: %s\n", inputFile)
		if err := p.fileManager.Remove(inputFile); err != nil {
			return fmt.Errorf("failed to delete source file: %w", err)
		}
		fmt.Printf("Source file deleted successfully\n")
	}

	return nil
}
