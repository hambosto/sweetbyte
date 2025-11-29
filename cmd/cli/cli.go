package cli

import (
	"fmt"

	"github.com/hambosto/sweetbyte/cmd/interactive"
	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/file"
	"github.com/hambosto/sweetbyte/internal/processor"
	"github.com/hambosto/sweetbyte/internal/types"
	"github.com/hambosto/sweetbyte/internal/ui"
	"github.com/spf13/cobra"
)

type CLI struct {
	rootCmd *cobra.Command
}

func NewCLI() *CLI {
	cli := &CLI{}
	cli.setupCommands()
	return cli
}

func (c *CLI) Execute() error {
	return c.rootCmd.Execute()
}

func (c *CLI) setupCommands() {
	c.rootCmd = &cobra.Command{
		Use:     "sweetbyte",
		Short:   "Multi-layered file encryption with error correction",
		Long:    "Encrypt files using AES-256-GCM and XChaCha20-Poly1305 with Reed-Solomon error correction. Run without arguments for interactive mode.",
		Version: config.AppVersion,
		Run: func(cmd *cobra.Command, args []string) {
			interactive.Run()
		},
	}

	c.rootCmd.AddCommand(c.createEncryptCommand())
	c.rootCmd.AddCommand(c.createDecryptCommand())
	c.rootCmd.AddCommand(c.createInteractiveCommand())
}

func (c *CLI) createEncryptCommand() *cobra.Command {
	var (
		inputFile    string
		outputFile   string
		password     string
		deleteSource bool
	)

	cmd := &cobra.Command{
		Use:   "encrypt [flags]",
		Short: "Encrypt a file with multi-layered encryption",
		Long:  "Compresses and encrypts files with AES-256-GCM and XChaCha20-Poly1305, plus Reed-Solomon error correction. Uses Argon2id for key derivation.",
		Example: `  sweetbyte encrypt -i document.txt -o document.txt.swx
  sweetbyte encrypt -i document.txt -p mypassword --delete-source`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return c.runEncrypt(inputFile, outputFile, password, deleteSource)
		},
	}

	cmd.Flags().StringVarP(&inputFile, "input", "i", "", "Input file to encrypt (required)")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file (default: input + .swx)")
	cmd.Flags().StringVarP(&password, "password", "p", "", "Encryption password (prompts if not provided)")
	cmd.Flags().BoolVar(&deleteSource, "delete-source", false, "Delete source file after encryption")

	if err := cmd.MarkFlagRequired("input"); err != nil {
		panic(fmt.Sprintf("failed to mark input flag as required: %v", err))
	}

	return cmd
}

func (c *CLI) createDecryptCommand() *cobra.Command {
	var (
		inputFile    string
		outputFile   string
		password     string
		deleteSource bool
	)

	cmd := &cobra.Command{
		Use:   "decrypt [flags]",
		Short: "Decrypt a file with error correction",
		Long:  "Verifies and corrects data corruption using Reed-Solomon codes, then decrypts with XChaCha20-Poly1305 and AES-256-GCM, and decompresses the file.",
		Example: `  sweetbyte decrypt -i document.txt.swx -o document.txt
  sweetbyte decrypt -i document.txt.swx -p mypassword
  sweetbyte decrypt -i document.txt.swx --delete-source`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return c.runDecrypt(inputFile, outputFile, password, deleteSource)
		},
	}

	cmd.Flags().StringVarP(&inputFile, "input", "i", "", "Input file to decrypt (required)")
	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file (default: removes .swx extension)")
	cmd.Flags().StringVarP(&password, "password", "p", "", "Decryption password (prompts if not provided)")
	cmd.Flags().BoolVar(&deleteSource, "delete-source", false, "Delete source file after decryption")

	if err := cmd.MarkFlagRequired("input"); err != nil {
		panic(fmt.Sprintf("failed to mark input flag as required: %v", err))
	}

	return cmd
}

func (c *CLI) createInteractiveCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "interactive",
		Short: "Start interactive mode",
		Long:  "Launch a guided interface for encrypting and decrypting files step-by-step.",
		Run: func(cmd *cobra.Command, args []string) {
			interactive.Run()
		},
	}
}

func (c *CLI) runEncrypt(inputFile, outputFile, password string, deleteSource bool) error {
	if err := file.ValidatePath(inputFile, true); err != nil {
		return fmt.Errorf("input file validation failed: %w", err)
	}

	if len(outputFile) == 0 {
		outputFile = file.GetOutputPath(inputFile, types.ModeEncrypt)
	}

	if err := file.ValidatePath(outputFile, false); err != nil {
		return fmt.Errorf("output file validation failed: %w", err)
	}

	return c.Encrypt(inputFile, outputFile, password, deleteSource)
}

func (c *CLI) runDecrypt(inputFile, outputFile, password string, deleteSource bool) error {
	if err := file.ValidatePath(inputFile, true); err != nil {
		return fmt.Errorf("input file validation failed: %w", err)
	}

	if len(outputFile) == 0 {
		outputFile = file.GetOutputPath(inputFile, types.ModeDecrypt)
		if outputFile == inputFile {
			return fmt.Errorf("cannot determine output filename, please specify with -o flag")
		}
	}

	if err := file.ValidatePath(outputFile, false); err != nil {
		return fmt.Errorf("output file validation failed: %w", err)
	}

	return c.Decrypt(inputFile, outputFile, password, deleteSource)
}

func (c *CLI) Encrypt(inputFile, outputFile, password string, deleteSource bool) error {
	if len(password) == 0 {
		var err error
		password, err = ui.GetEncryptionPassword()
		if err != nil {
			return fmt.Errorf("failed to get password: %w", err)
		}
	}

	if err := processor.Encryption(inputFile, outputFile, password); err != nil {
		return fmt.Errorf("failed to encrypt %s: %w", inputFile, err)
	}

	ui.ShowSuccessInfo(types.ModeEncrypt, outputFile)
	if deleteSource {
		if err := file.Remove(inputFile); err != nil {
			return fmt.Errorf("failed to delete source file: %w", err)
		}
		ui.ShowSourceDeleted(inputFile)
	}

	return nil
}

func (c *CLI) Decrypt(inputFile, outputFile, password string, deleteSource bool) error {
	if len(password) == 0 {
		var err error
		password, err = ui.GetDecryptionPassword()
		if err != nil {
			return fmt.Errorf("failed to get password: %w", err)
		}
	}

	if err := processor.Decryption(inputFile, outputFile, password); err != nil {
		return fmt.Errorf("failed to decrypt %s: %w", inputFile, err)
	}

	ui.ShowSuccessInfo(types.ModeDecrypt, outputFile)
	if deleteSource {
		if err := file.Remove(inputFile); err != nil {
			return fmt.Errorf("failed to delete source file: %w", err)
		}
		ui.ShowSourceDeleted(inputFile)
	}

	return nil
}
