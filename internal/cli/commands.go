// Package cli provides the command-line interface functionality for SweetByte.
package cli

import (
	"fmt"
	"os"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/interactive"
	"github.com/spf13/cobra"
)

// Commands represents the command-line interface of the application.
type Commands struct {
	rootCmd *cobra.Command
}

// NewCommands creates a new Commands instance and sets up the commands.
func NewCommands() *Commands {
	cli := &Commands{}
	cli.setupCommands()
	return cli
}

// Execute runs the root command of the Commands.
func (c *Commands) Execute() error {
	return c.rootCmd.Execute()
}

// setupCommands sets up the root command and all subcommands.
func (c *Commands) setupCommands() {
	c.rootCmd = &cobra.Command{
		Use:   "sweetbyte",
		Short: "A tool for multi-layered file encryption and error correction.",
		Long: `SweetByte secures your files through a multi-layered process that includes compression,
dual-layer encryption with AES-256-GCM and XChaCha20-Poly1305, and Reed-Solomon error
correction codes. This ensures both confidentiality and resilience against data corruption.

SweetByte can be run in a user-friendly interactive mode or via the command line for automation.`,
		Version: config.AppVersion,
		Run: func(cmd *cobra.Command, args []string) {
			// If no command is specified, run the interactive mode.
			interactiveApp := interactive.NewInteractive()
			interactiveApp.Run()
		},
	}

	// Add the encrypt, decrypt, and interactive commands.
	c.rootCmd.AddCommand(c.createEncryptCommand())
	c.rootCmd.AddCommand(c.createDecryptCommand())
	c.rootCmd.AddCommand(c.createInteractiveCommand())
}

// createEncryptCommand creates the encrypt command.
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
		Short: "Encrypts a file using a multi-layered approach.",
		Long: `This command secures a file by first compressing it, then encrypting it with two independent
layers of state-of-the-art ciphers: AES-256-GCM followed by XChaCha20-Poly1305. Finally,
it applies Reed-Solomon error correction codes to the ciphertext, protecting it from
corruption. A strong encryption key is derived from your password using Argon2id.`,
		Example: `  sweetbyte encrypt -i document.txt -o document.txt.swb
  sweetbyte encrypt -i document.txt -p mypassword --delete-source
  sweetbyte encrypt -i document.txt --secure-delete`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return c.runEncrypt(inputFile, outputFile, password, deleteSource, secureDelete)
		},
	}

	// Add flags for the encrypt command.
	cmd.Flags().StringVarP(&inputFile, "input", "i", "", "Input file to encrypt (required)")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output encrypted file (default: input + .swb)")
	cmd.Flags().StringVarP(&password, "password", "p", "", "Encryption password (will prompt if not provided)")
	cmd.Flags().BoolVar(&deleteSource, "delete-source", false, "Delete source file after encryption")
	cmd.Flags().BoolVar(&secureDelete, "secure-delete", false, "Use secure deletion (slower but unrecoverable)")

	// Mark the input flag as required.
	if err := cmd.MarkFlagRequired("input"); err != nil {
		panic(fmt.Sprintf("failed to mark input flag as required: %v", err))
	}

	return cmd
}

// createDecryptCommand creates the decrypt command.
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
		Short: "Decrypts a file encrypted by SweetByte.",
		Long: `This command reverses the encryption process. It first uses the Reed-Solomon codes to
verify and correct any data corruption, then decrypts the data through two layers
(XChaCha20-Poly1305 and AES-256-GCM), and finally decompresses it to restore the original
file. The correct password is required to derive the necessary decryption key.`,
		Example: `  sweetbyte decrypt -i document.txt.swb -o document.txt
  sweetbyte decrypt -i document.txt.swb -p mypassword
  sweetbyte decrypt -i document.txt.swb --delete-source`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return c.runDecrypt(inputFile, outputFile, password, deleteSource, secureDelete)
		},
	}

	// Add flags for the decrypt command.
	cmd.Flags().StringVarP(&inputFile, "input", "i", "", "Input file to decrypt (required)")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output decrypted file (default: remove .swb extension)")
	cmd.Flags().StringVarP(&password, "password", "p", "", "Decryption password (will prompt if not provided)")
	cmd.Flags().BoolVar(&deleteSource, "delete-source", false, "Delete source file after decryption")
	cmd.Flags().BoolVar(&secureDelete, "secure-delete", false, "Use secure deletion (slower but unrecoverable)")

	// Mark the input flag as required.
	if err := cmd.MarkFlagRequired("input"); err != nil {
		panic(fmt.Sprintf("failed to mark input flag as required: %v", err))
	}

	return cmd
}

// createInteractiveCommand creates the interactive command.
func (c *Commands) createInteractiveCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "interactive",
		Short: "Starts a guided session for multi-layered encryption and decryption.",
		Long: `This command launches SweetByte in interactive mode, providing a step-by-step guided
experience for encrypting and decrypting files using the multi-layered security process.
This is ideal for users who prefer a more intuitive and user-friendly interface.`,
		Run: func(cmd *cobra.Command, args []string) {
			// Run the interactive mode.
			interactiveApp := interactive.NewInteractive()
			interactiveApp.Run()
		},
	}
}

// runEncrypt runs the encryption process.
func (c *Commands) runEncrypt(inputFile, outputFile, password string, deleteSource, secureDelete bool) error {
	// Check if the input file exists.
	if _, err := os.Stat(inputFile); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("input file not found: %s", inputFile)
		}
		return fmt.Errorf("failed to access input file %s: %w", inputFile, err)
	}

	// If the output file is not specified, create a default name.
	if len(outputFile) == 0 {
		outputFile = inputFile + config.FileExtension
	}

	// Check if the output file already exists.
	if _, err := os.Stat(outputFile); err == nil {
		return fmt.Errorf("output file already exists: %s", outputFile)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to access output file %s: %w", outputFile, err)
	}

	// Create a new Commands processor and run the encryption.
	processor := NewCLI()
	return processor.Encrypt(inputFile, outputFile, password, deleteSource, secureDelete)
}

// runDecrypt runs the decryption process.
func (c *Commands) runDecrypt(inputFile, outputFile, password string, deleteSource, secureDelete bool) error {
	// Check if the input file exists.
	if _, err := os.Stat(inputFile); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("input file not found: %s", inputFile)
		}
		return fmt.Errorf("failed to access input file %s: %w", inputFile, err)
	}

	// If the output file is not specified, create a default name.
	if len(outputFile) == 0 {
		if len(inputFile) > len(config.FileExtension) &&
			inputFile[len(inputFile)-len(config.FileExtension):] == config.FileExtension {
			outputFile = inputFile[:len(inputFile)-len(config.FileExtension)]
		} else {
			return fmt.Errorf("cannot determine output filename, please specify with -o flag")
		}
	}

	// Check if the output file already exists.
	if _, err := os.Stat(outputFile); err == nil {
		return fmt.Errorf("output file already exists: %s", outputFile)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("failed to access output file %s: %w", outputFile, err)
	}

	// Create a new Commands processor and run the decryption.
	processor := NewCLI()
	return processor.Decrypt(inputFile, outputFile, password, deleteSource, secureDelete)
}
