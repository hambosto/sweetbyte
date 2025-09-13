// Package ui provides user interface functionalities.
package ui

import (
	"fmt"
	"strconv"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"github.com/hambosto/sweetbyte/internal/files"
	"github.com/hambosto/sweetbyte/internal/options"
	"github.com/hambosto/sweetbyte/internal/utils"
)

var (
	successStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("2")) // Green
	boldStyle    = lipgloss.NewStyle().Bold(true)
)

// ShowFileInfo displays information about a list of files.
func ShowFileInfo(files []files.FileInfo) {
	if len(files) == 0 {
		fmt.Println("No files found.")
		return
	}

	fmt.Println()
	fmt.Printf("%s %s ", successStyle.Render("✓"), boldStyle.Render(fmt.Sprintf("Found %d file(s):", len(files))))
	fmt.Println()

	// Create table with headers
	t := table.New().
		Headers("No", "Name", "Size", "Status").
		Border(lipgloss.NormalBorder()).
		BorderStyle(boldStyle)

	// Add rows to the table
	for i, fi := range files {
		fileStatus := "unencrypted"
		if fi.IsEncrypted {
			fileStatus = "encrypted"
		}

		// Truncate filename if too long
		filename := fi.Path
		if len(filename) > 28 { // Leave 2 chars for padding
			filename = filename[:25] + "..."
		}

		// Style each cell
		no := boldStyle.Render(strconv.Itoa(i + 1))
		name := successStyle.Render(filename)
		size := boldStyle.Render(utils.FormatBytes(fi.Size))
		status := boldStyle.Render(fileStatus)

		t = t.Row(no, name, size, status)
	}

	fmt.Println(t)
	fmt.Println()
}

// ShowProcessingInfo displays information about the file being processed.
func ShowProcessingInfo(mode options.ProcessorMode, file string) {
	action := "Encrypting"
	if mode == options.ModeDecrypt {
		action = "Decrypting"
	}
	fmt.Println()
	fmt.Printf("%s %s ", successStyle.Render("✓"), boldStyle.Render(fmt.Sprintf("%s file: %s", action, file)))
	fmt.Println()
}

// ShowSuccessInfo displays a success message for encryption or decryption.
func ShowSuccessInfo(mode options.ProcessorMode, destPath string) {
	action := "encrypted"
	if mode == options.ModeDecrypt {
		action = "decrypted"
	}

	fmt.Println()
	fmt.Printf("%s %s ", successStyle.Render("✓"), boldStyle.Render(fmt.Sprintf("File %s successfully: %s", action, destPath)))
	fmt.Println()
}

// ShowSourceDeleted displays a message indicating that the source file was deleted.
func ShowSourceDeleted(inputPath string) {
	fmt.Printf("%s %s ", successStyle.Render("✓"), boldStyle.Render(fmt.Sprintf("Source file deleted: %s", inputPath)))
	fmt.Println()
}
