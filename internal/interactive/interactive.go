package interactive

import (
	"fmt"
	"os"

	"github.com/hambosto/sweetbyte/internal/files"
	"github.com/hambosto/sweetbyte/internal/operations"
	"github.com/hambosto/sweetbyte/internal/options"
	"github.com/hambosto/sweetbyte/internal/ui"
)

type InteractiveApp struct {
	terminal    *ui.Terminal
	prompt      *ui.Prompt
	fileManager *files.Manager
	fileFinder  *files.Finder
	encryptor   *operations.Encryptor
	decryptor   *operations.Decryptor
}

func NewInteractiveApp() *InteractiveApp {
	return &InteractiveApp{
		terminal:    ui.NewTerminal(),
		prompt:      ui.NewPrompt(),
		fileManager: files.NewManager(),
		fileFinder:  files.NewFinder(),
		encryptor:   operations.NewEncryptor(),
		decryptor:   operations.NewDecryptor(),
	}
}

func (a *InteractiveApp) Run() {
	a.initializeTerminal()
	a.terminal.PrintBanner()

	if err := a.runInteractiveLoop(); err != nil {
		a.handleError(err)
		os.Exit(1)
	}

	a.terminal.Cleanup()
}

func (a *InteractiveApp) initializeTerminal() {
	a.terminal.Clear()
	a.terminal.MoveTopLeft()
}

func (a *InteractiveApp) runInteractiveLoop() error {
	operation, err := a.prompt.GetProcessingMode()
	if err != nil {
		return fmt.Errorf("failed to get processing mode: %w", err)
	}

	eligibleFiles, err := a.getEligibleFiles(operation)
	if err != nil {
		return err
	}

	fileInfos, err := a.fileFinder.GetFileInfo(eligibleFiles)
	if err != nil {
		return fmt.Errorf("failed to get file information: %w", err)
	}
	a.prompt.ShowFileInfo(fileInfos)

	selectedFile, err := a.prompt.ChooseFile(eligibleFiles)
	if err != nil {
		return fmt.Errorf("failed to select file: %w", err)
	}

	a.prompt.ShowProcessingInfo(operation, selectedFile)

	if err := a.processFile(selectedFile, operation); err != nil {
		return fmt.Errorf("failed to process file '%s': %w", selectedFile, err)
	}

	return nil
}

func (a *InteractiveApp) handleError(err error) {
	a.terminal.PrintError(fmt.Sprintf("Application error: %v", err))
}

func (a *InteractiveApp) getEligibleFiles(operation options.ProcessorMode) ([]string, error) {
	eligibleFiles, err := a.fileFinder.FindEligibleFiles(operation)
	if err != nil {
		return nil, fmt.Errorf("failed to find eligible files: %w", err)
	}

	if len(eligibleFiles) == 0 {
		return nil, fmt.Errorf("no eligible files found for %s operation", operation)
	}

	return eligibleFiles, nil
}

func (a *InteractiveApp) processFile(inputPath string, mode options.ProcessorMode) error {
	outputPath := a.fileFinder.GetOutputPath(inputPath, mode)

	if err := a.fileManager.ValidatePath(inputPath, true); err != nil {
		return fmt.Errorf("source validation failed: %w", err)
	}

	if err := a.fileManager.ValidatePath(outputPath, false); err != nil {
		if confirm, confirmErr := a.prompt.ConfirmFileOverwrite(outputPath); confirmErr != nil || !confirm {
			return fmt.Errorf("operation canceled by user")
		}
	}

	var err error
	switch mode {
	case options.ModeEncrypt:
		err = a.encryptFile(inputPath, outputPath)
	case options.ModeDecrypt:
		err = a.decryptFile(inputPath, outputPath)
	default:
		return fmt.Errorf("unknown processing mode: %v", mode)
	}

	if err != nil {
		return err
	}

	a.prompt.ShowSuccess(fmt.Sprintf("File processed successfully: %s", outputPath))

	var fileType string
	if mode == options.ModeEncrypt {
		fileType = "original"
	} else {
		fileType = "encrypted"
	}

	if shouldDelete, deleteType, err := a.prompt.ConfirmFileRemoval(inputPath, fmt.Sprintf("Delete %s file", fileType)); err == nil && shouldDelete {
		if err := a.fileManager.Remove(inputPath, deleteType); err != nil {
			return fmt.Errorf("failed to delete source file: %w", err)
		}
		a.prompt.ShowSuccess(fmt.Sprintf("Source file deleted: %s", inputPath))
	}

	return nil
}

func (a *InteractiveApp) encryptFile(srcPath, destPath string) error {
	password, err := a.prompt.GetEncryptionPassword()
	if err != nil {
		return fmt.Errorf("password prompt failed: %w", err)
	}

	if err := a.encryptor.EncryptFile(srcPath, destPath, password); err != nil {
		return fmt.Errorf("failed to encrypt '%s': %w", srcPath, err)
	}

	return nil
}

func (a *InteractiveApp) decryptFile(srcPath, destPath string) error {
	password, err := a.prompt.GetDecryptionPassword()
	if err != nil {
		return fmt.Errorf("password prompt failed: %w", err)
	}

	if err := a.decryptor.DecryptFile(srcPath, destPath, password); err != nil {
		return fmt.Errorf("failed to decrypt '%s': %w", srcPath, err)
	}

	return nil
}
