package tui

import (
	"fmt"
	"strconv"

	"sweetbyte/options"
	"sweetbyte/utils"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
)

var (
	successStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	boldStyle    = lipgloss.NewStyle().Bold(true)
)

func ShowFileInfo(filePaths []string, fileSizes []int64, fileEncrypted []bool) {
	if len(filePaths) == 0 {
		fmt.Println("No files found.")
		return
	}

	if len(filePaths) != len(fileSizes) || len(filePaths) != len(fileEncrypted) {
		fmt.Println("Error: Mismatched input arrays.")
		return
	}

	fmt.Println()
	fmt.Printf("%s %s ", successStyle.Render("✓"), boldStyle.Render(fmt.Sprintf("Found %d file(s):", len(filePaths))))
	fmt.Println()

	t := table.New().
		Headers("No", "Name", "Size", "Status").
		Border(lipgloss.NormalBorder()).
		BorderStyle(boldStyle)

	for i := range filePaths {
		fileStatus := "unencrypted"
		if fileEncrypted[i] {
			fileStatus = "encrypted"
		}

		filename := filePaths[i]
		if len(filename) > 28 {
			filename = filename[:25] + "..."
		}

		no := boldStyle.Render(strconv.Itoa(i + 1))
		name := successStyle.Render(filename)
		size := boldStyle.Render(utils.FormatBytes(fileSizes[i]))
		status := boldStyle.Render(fileStatus)

		t = t.Row(no, name, size, status)
	}

	fmt.Println(t)
	fmt.Println()
}

func ShowProcessingInfo(mode options.ProcessorMode, file string) {
	action := "Encrypting"
	if mode == options.ModeDecrypt {
		action = "Decrypting"
	}
	fmt.Println()
	fmt.Printf("%s %s ", successStyle.Render("✓"), boldStyle.Render(fmt.Sprintf("%s file: %s", action, file)))
	fmt.Println()
}

func ShowSuccessInfo(mode options.ProcessorMode, destPath string) {
	action := "encrypted"
	if mode == options.ModeDecrypt {
		action = "decrypted"
	}

	fmt.Println()
	fmt.Printf("%s %s ", successStyle.Render("✓"), boldStyle.Render(fmt.Sprintf("File %s successfully: %s", action, destPath)))
	fmt.Println()
}

func ShowSourceDeleted(inputPath string) {
	fmt.Printf("%s %s ", successStyle.Render("✓"), boldStyle.Render(fmt.Sprintf("Source file deleted: %s", inputPath)))
	fmt.Println()
}
