package cli

import (
	"fmt"
	"os"

	"sweetbyte/cmd/interactive"
	"sweetbyte/config"

	"github.com/spf13/cobra"
)

type Commands struct {
	rootCmd *cobra.Command
}

func NewCommands() *Commands {
	cli := &Commands{}
	cli.setupCommands()
	return cli
}

func (c *Commands) Execute() error {
	return c.rootCmd.Execute()
}

func (c *Commands) setupCommands() {
	c.rootCmd = &cobra.Command{
		Use:   "sweetbyte",
		Short: "Multi-layered file encryption tool with error correction.",
		Long: `SweetByte encrypts files using multiple layers of encryption with AES-256-GCM and 
XChaCha20-Poly1305, plus Reed-Solomon error correction for data resilience.
Run without arguments to start interactive mode.`,
		Version: config.AppVersion,
		Run: func(cmd *cobra.Command, args []string) {
			interactiveApp := interactive.NewInteractive()
			interactiveApp.Run()
		},
	}

	c.rootCmd.AddCommand(c.createEncryptCommand())
	c.rootCmd.AddCommand(c.createDecryptCommand())
	c.rootCmd.AddCommand(c.createInteractiveCommand())
}

func (c *Commands) createEncryptCommand() *cobra.Command {
	var (
		inputFile    string
		outputFile   string
		password     string
		deleteSource bool
		secureDelete bool
	)

	cmd := &cobra.Command{
		Use:   "encrypt [flags]",
		Short: "Encrypts a file with multiple layers of encryption.",
		Long: `This command compresses the file, then encrypts it with two layers:
AES-256-GCM followed by XChaCha20-Poly1305. It also applies Reed-Solomon
error correction codes for data resilience. The encryption key is derived
from your password using Argon2id.`,
		Example: `  sweetbyte encrypt -i document.txt -o document.txt.swb
  sweetbyte encrypt -i document.txt -p mypassword --delete-source
  sweetbyte encrypt -i document.txt --secure-delete`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return c.runEncrypt(inputFile, outputFile, password, deleteSource, secureDelete)
		},
	}

	cmd.Flags().StringVarP(&inputFile, "input", "i", "", "Input file to encrypt (required)")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output encrypted file (default: input + .swb)")
	cmd.Flags().StringVarP(&password, "password", "p", "", "Encryption password (will prompt if not provided)")
	cmd.Flags().BoolVar(&deleteSource, "delete-source", false, "Delete source file after encryption")
	cmd.Flags().BoolVar(&secureDelete, "secure-delete", false, "Use secure deletion (slower but unrecoverable)")

	if err := cmd.MarkFlagRequired("input"); err != nil {
		panic(fmt.Sprintf("failed to mark input flag as required: %v", err))
	}

	return cmd
}

func (c *Commands) createDecryptCommand() *cobra.Command {
	var (
		inputFile    string
		outputFile   string
		password     string
		deleteSource bool
		secureDelete bool
	)

	cmd := &cobra.Command{
		Use:   "decrypt [flags]",
		Short: "Decrypts a file with error correction and multiple layers.",
		Long: `This command first uses Reed-Solomon codes to verify and correct any data 
corruption, then decrypts with two layers (XChaCha20-Poly1305 and AES-256-GCM), 
and finally decompresses to restore the original file. The correct password is 
required to derive the decryption key.`,
		Example: `  sweetbyte decrypt -i document.txt.swb -o document.txt
  sweetbyte decrypt -i document.txt.swb -p mypassword
  sweetbyte decrypt -i document.txt.swb --delete-source`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return c.runDecrypt(inputFile, outputFile, password, deleteSource, secureDelete)
		},
	}

	cmd.Flags().StringVarP(&inputFile, "input", "i", "", "Input file to decrypt (required)")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output decrypted file (default: remove .swb extension)")
	cmd.Flags().StringVarP(&password, "password", "p", "", "Decryption password (will prompt if not provided)")
	cmd.Flags().BoolVar(&deleteSource, "delete-source", false, "Delete source file after decryption")
	cmd.Flags().BoolVar(&secureDelete, "secure-delete", false, "Use secure deletion (slower but unrecoverable)")

	if err := cmd.MarkFlagRequired("input"); err != nil {
		panic(fmt.Sprintf("failed to mark input flag as required: %v", err))
	}

	return cmd
}

func (c *Commands) createInteractiveCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "interactive",
		Short: "Starts a guided session for encryption and decryption.",
		Long: `This command launches SweetByte in interactive mode with a step-by-step
interface for encrypting and decrypting files using the multi-layered security process.`,
		Run: func(cmd *cobra.Command, args []string) {
			interactiveApp := interactive.NewInteractive()
			interactiveApp.Run()
		},
	}
}

func (c *Commands) runEncrypt(inputFile, outputFile, password string, deleteSource, secureDelete bool) error {
	if _, err := os.Stat(inputFile); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("input file not found: %s", inputFile)
		}
		return fmt.Errorf("failed to access input file %s: %w", inputFile, err)
	}

	if len(outputFile) == 0 {
		outputFile = inputFile + config.FileExtension
	}

	if _, err := os.Stat(outputFile); err == nil {
		return fmt.Errorf("output file already exists: %s", outputFile)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to access output file %s: %w", outputFile, err)
	}

	processor := NewCLI()
	return processor.Encrypt(inputFile, outputFile, password, deleteSource, secureDelete)
}

func (c *Commands) runDecrypt(inputFile, outputFile, password string, deleteSource, secureDelete bool) error {
	if _, err := os.Stat(inputFile); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("input file not found: %s", inputFile)
		}
		return fmt.Errorf("failed to access input file %s: %w", inputFile, err)
	}

	if len(outputFile) == 0 {
		if len(inputFile) > len(config.FileExtension) &&
			inputFile[len(inputFile)-len(config.FileExtension):] == config.FileExtension {
			outputFile = inputFile[:len(inputFile)-len(config.FileExtension)]
		} else {
			return fmt.Errorf("cannot determine output filename, please specify with -o flag")
		}
	}

	if _, err := os.Stat(outputFile); err == nil {
		return fmt.Errorf("output file already exists: %s", outputFile)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to access output file %s: %w", outputFile, err)
	}

	processor := NewCLI()
	return processor.Decrypt(inputFile, outputFile, password, deleteSource, secureDelete)
}
