// Package ui provides user interface functionalities.
package ui

import (
	"fmt"
	"strconv"

	"github.com/alperdrsnn/clime"
	"github.com/hambosto/sweetbyte/internal/files"
	"github.com/hambosto/sweetbyte/internal/options"
	"github.com/hambosto/sweetbyte/internal/utils"
)

// ShowFileInfo displays information about a list of files.
func ShowFileInfo(files []files.FileInfo) {
	if len(files) == 0 {
		fmt.Println("No files found.")
		return
	}

	fmt.Println()
	fmt.Printf("%s %s ", clime.Success.Sprint("✓"), clime.BoldColor.Sprintf("Found %d file(s):", len(files)))
	fmt.Println()

	table := clime.NewTable().
		AddColumn("No").
		AddColumn("Name").
		AddColumn("Size").
		AddColumn("Status").
		SetColumnColor(0, clime.BoldColor).
		SetColumnColor(1, clime.Success).
		SetColumnColor(2, clime.BoldColor).
		SetColumnColor(3, clime.BoldColor).
		WithBorderColor(clime.BoldColor)

	for i, fi := range files {
		status := "unencrypted"
		if fi.IsEncrypted {
			status = "encrypted"
		}

		// Truncate filename if too long
		filename := fi.Path
		if len(filename) > 28 { // Leave 2 chars for padding
			filename = filename[:25] + "..."
		}

		table.AddRow(strconv.Itoa(i+1), filename, utils.FormatBytes(fi.Size), status)
	}

	table.Print()
	fmt.Println()
}

// ShowProcessingInfo displays information about the file being processed.
func ShowProcessingInfo(mode options.ProcessorMode, file string) {
	action := "Encrypting"
	if mode == options.ModeDecrypt {
		action = "Decrypting"
	}
	fmt.Println()
	fmt.Printf("%s %s ", clime.Success.Sprint("✓"), clime.BoldColor.Sprintf("%s file: %s", action, file))
	fmt.Println()
}

// ShowSuccessInfo displays a success message for encryption or decryption.
func ShowSuccessInfo(mode options.ProcessorMode, destPath string) {
	action := "encrypted"
	if mode == options.ModeDecrypt {
		action = "decrypted"
	}

	fmt.Println()
	fmt.Printf("%s %s ", clime.Success.Sprint("✓"), clime.BoldColor.Sprintf("File %s successfully: %s", action, destPath))
	fmt.Println()
}

// ShowSourceDeleted displays a message indicating that the source file was deleted.
func ShowSourceDeleted(inputPath string) {
	fmt.Printf("%s %s ", clime.Success.Sprint("✓"), clime.BoldColor.Sprintf("Source file deleted: %s", inputPath))
	fmt.Println()
}
