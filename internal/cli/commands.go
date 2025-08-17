// Package cli provides the command-line interface (CLI) implementation for the SweetByte application.
// It defines the CLI commands and their underlying processing logic for file encryption and decryption.
package cli

import (
	"fmt"
	"os"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/interactive"
	"github.com/spf13/cobra"
)

// CLI represents the command-line interface application.
// It holds the root command and manages the setup of all subcommands
// for encryption, decryption, and interactive mode.
type CLI struct {
	rootCmd *cobra.Command // The root Cobra command for the CLI application.
}

// NewCLI creates and returns a new CLI instance.
// It initializes the root command and sets up all available subcommands.
func NewCLI() *CLI {
	cli := &CLI{}       // Create a new CLI struct.
	cli.setupCommands() // Set up all Cobra commands.
	return cli
}

// Execute runs the root command of the CLI application.
// This is the entry point for processing command-line arguments.
func (c *CLI) Execute() error {
	return c.rootCmd.Execute() // Execute the root Cobra command.
}

// setupCommands initializes the root Cobra command and adds all subcommands
// for encrypt, decrypt, and interactive operations.
func (c *CLI) setupCommands() {
	c.rootCmd = &cobra.Command{
		Use:   "sweetbyte",                                                      // The primary command name.
		Short: "A tool for multi-layered file encryption and error correction.", // Short description shown in help.
		Long: `SweetByte secures your files through a multi-layered process that includes compression,
dual-layer encryption with AES-256-GCM and XChaCha20-Poly1305, and Reed-Solomon error
correction codes. This ensures both confidentiality and resilience against data corruption.

SweetByte can be run in a user-friendly interactive mode or via the command line for automation.`,
		Version: config.AppVersion, // Application version, automatically managed by Cobra.
		Run: func(cmd *cobra.Command, args []string) { // Default action if no subcommand is given.
			interactiveApp := interactive.NewInteractiveApp() // Initialize the interactive application.
			interactiveApp.Run()                              // Run the interactive application.
		},
	}

	// Add subcommands to the root command.
	c.rootCmd.AddCommand(c.createEncryptCommand())
	c.rootCmd.AddCommand(c.createDecryptCommand())
	c.rootCmd.AddCommand(c.createInteractiveCommand())
}

// createEncryptCommand creates and configures the `encrypt` subcommand.
// It defines flags for input/output files, password, and deletion options.
func (c *CLI) createEncryptCommand() *cobra.Command {
	// Declare variables to hold flag values.
	var (
		inputFile    string // Path to the file to be encrypted.
		outputFile   string // Path for the encrypted output file.
		password     string // Password for encryption; can be empty to prompt.
		deleteSource bool   // Flag to indicate if the source file should be deleted.
		secureDelete bool   // Flag to indicate if secure deletion should be used.
	)

	cmd := &cobra.Command{
		Use:   "encrypt [flags]",                                 // How the command is used.
		Short: "Encrypts a file using a multi-layered approach.", // Short description.
		Long: `This command secures a file by first compressing it, then encrypting it with two independent
layers of state-of-the-art ciphers: AES-256-GCM followed by XChaCha20-Poly1305. Finally,
it applies Reed-Solomon error correction codes to the ciphertext, protecting it from
corruption. A strong encryption key is derived from your password using Argon2id.`,
		Example: `  sweetbyte encrypt -i document.txt -o document.txt.swb
  sweetbyte encrypt -i document.txt -p mypassword --delete-source
  sweetbyte encrypt -i document.txt --secure-delete`,
		RunE: func(cmd *cobra.Command, args []string) error { // Function to run when the command is executed.
			return c.runEncrypt(inputFile, outputFile, password, deleteSource, secureDelete) // Call the encryption logic.
		},
	}

	// Define command-line flags and bind them to variables.
	cmd.Flags().StringVarP(&inputFile, "input", "i", "", "Input file to encrypt (required)")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output encrypted file (default: input + .swb)")
	cmd.Flags().StringVarP(&password, "password", "p", "", "Encryption password (will prompt if not provided)")
	cmd.Flags().BoolVar(&deleteSource, "delete-source", false, "Delete source file after encryption")
	cmd.Flags().BoolVar(&secureDelete, "secure-delete", false, "Use secure deletion (slower but unrecoverable)")

	// Mark the 'input' flag as required, ensuring the user provides it.
	if err := cmd.MarkFlagRequired("input"); err != nil {
		panic(fmt.Sprintf("failed to mark input flag as required: %v", err)) // Panic if marking flag fails (should not happen).
	}

	return cmd // Return the configured encrypt command.
}

// createDecryptCommand creates and configures the `decrypt` subcommand.
// It defines flags for input/output files, password, and deletion options.
func (c *CLI) createDecryptCommand() *cobra.Command {
	// Declare variables to hold flag values.
	var (
		inputFile    string // Path to the file to be decrypted.
		outputFile   string // Path for the decrypted output file.
		password     string // Password for decryption; can be empty to prompt.
		deleteSource bool   // Flag to indicate if the source file should be deleted.
		secureDelete bool   // Flag to indicate if secure deletion should be used.
	)

	cmd := &cobra.Command{
		Use:   "decrypt [flags]",                         // How the command is used.
		Short: "Decrypts a file encrypted by SweetByte.", // Short description.
		Long: `This command reverses the encryption process. It first uses the Reed-Solomon codes to
verify and correct any data corruption, then decrypts the data through two layers
(XChaCha20-Poly1305 and AES-256-GCM), and finally decompresses it to restore the original
file. The correct password is required to derive the necessary decryption key.`,
		Example: `  sweetbyte decrypt -i document.txt.swb -o document.txt
  sweetbyte decrypt -i document.txt.swb -p mypassword
  sweetbyte decrypt -i document.txt.swb --delete-source`,
		RunE: func(cmd *cobra.Command, args []string) error { // Function to run when the command is executed.
			return c.runDecrypt(inputFile, outputFile, password, deleteSource, secureDelete) // Call the decryption logic.
		},
	}

	// Define command-line flags and bind them to variables.
	cmd.Flags().StringVarP(&inputFile, "input", "i", "", "Input file to decrypt (required)")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output decrypted file (default: remove .swb extension)")
	cmd.Flags().StringVarP(&password, "password", "p", "", "Decryption password (will prompt if not provided)")
	cmd.Flags().BoolVar(&deleteSource, "delete-source", false, "Delete source file after decryption")
	cmd.Flags().BoolVar(&secureDelete, "secure-delete", false, "Use secure deletion (slower but unrecoverable)")

	// Mark the 'input' flag as required, ensuring the user provides it.
	if err := cmd.MarkFlagRequired("input"); err != nil {
		panic(fmt.Sprintf("failed to mark input flag as required: %v", err)) // Panic if marking flag fails.
	}

	return cmd // Return the configured decrypt command.
}

// createInteractiveCommand creates and configures the `interactive` subcommand.
// This command launches the SweetByte application in its user-friendly interactive mode.
func (c *CLI) createInteractiveCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "interactive",                                                          // How the command is used.
		Short: "Starts a guided session for multi-layered encryption and decryption.", // Short description.
		Long: `This command launches SweetByte in interactive mode, providing a step-by-step guided
experience for encrypting and decrypting files using the multi-layered security process.
This is ideal for users who prefer a more intuitive and user-friendly interface.`,
		Run: func(cmd *cobra.Command, args []string) { // Function to run when the command is executed.
			interactiveApp := interactive.NewInteractiveApp() // Initialize the interactive application.
			interactiveApp.Run()                              // Run the interactive application.
		},
	}
}

// runEncrypt is the execution logic for the `encrypt` command.
// It performs validation on input/output paths and then delegates to the CLIProcessor for the actual encryption.
func (c *CLI) runEncrypt(inputFile, outputFile, password string, deleteSource, secureDelete bool) error {
	// Verify that the input file exists and is accessible.
	if _, err := os.Stat(inputFile); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("input file not found: %s", inputFile) // Error if input file does not exist.
		}
		return fmt.Errorf("failed to access input file %s: %w", inputFile, err) // Other access errors.
	}

	// If no output file is specified, generate a default one.
	if outputFile == "" {
		outputFile = inputFile + config.FileExtension // Append the default encrypted file extension.
	}

	// Check if the output file already exists to prevent accidental overwrites.
	if _, err := os.Stat(outputFile); err == nil { // If os.Stat returns no error, file exists.
		return fmt.Errorf("output file already exists: %s", outputFile) // Error if output file exists.
	} else if !os.IsNotExist(err) { // Handle other errors when checking output file existence.
		return fmt.Errorf("failed to access output file %s: %w", outputFile, err)
	}

	processor := NewCLIProcessor()                                                        // Create a new CLIProcessor to handle the encryption logic.
	return processor.Encrypt(inputFile, outputFile, password, deleteSource, secureDelete) // Delegate to the processor.
}

// runDecrypt is the execution logic for the `decrypt` command.
// It performs validation on input/output paths and then delegates to the CLIProcessor for the actual decryption.
func (c *CLI) runDecrypt(inputFile, outputFile, password string, deleteSource, secureDelete bool) error {
	// Verify that the input encrypted file exists and is accessible.
	if _, err := os.Stat(inputFile); err != nil {
		if os.IsNotExist(err) {
			return fmt.Errorf("input file not found: %s", inputFile) // Error if input file does not exist.
		}
		return fmt.Errorf("failed to access input file %s: %w", inputFile, err) // Other access errors.
	}

	// If no output file is specified, generate a default one by removing the .swb extension.
	if outputFile == "" {
		if len(inputFile) > len(config.FileExtension) && // Ensure the input file name is long enough.
			inputFile[len(inputFile)-len(config.FileExtension):] == config.FileExtension { // Check if it ends with the .swb extension.
			outputFile = inputFile[:len(inputFile)-len(config.FileExtension)] // Remove the extension.
		} else {
			return fmt.Errorf("cannot determine output filename, please specify with -o flag") // Error if extension cannot be removed.
		}
	}

	// Check if the output file already exists to prevent accidental overwrites.
	if _, err := os.Stat(outputFile); err == nil { // If os.Stat returns no error, file exists.
		return fmt.Errorf("output file already exists: %s", outputFile) // Error if output file exists.
	} else if !os.IsNotExist(err) { // Handle other errors when checking output file existence.
		return fmt.Errorf("failed to access output file %s: %w", outputFile, err)
	}

	processor := NewCLIProcessor()                                                        // Create a new CLIProcessor to handle the decryption logic.
	return processor.Decrypt(inputFile, outputFile, password, deleteSource, secureDelete) // Delegate to the processor.
}
