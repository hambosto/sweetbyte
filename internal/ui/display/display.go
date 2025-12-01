package display

import (
	"fmt"
	"strconv"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
	"github.com/hambosto/sweetbyte/internal/types"
	"github.com/hambosto/sweetbyte/internal/utils"
)

var (
	successStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("2"))
	boldStyle    = lipgloss.NewStyle().Bold(true)
)

func ShowFileInfo(filePaths []string, fileSizes []int64, fileEncrypted []bool) error {
	if len(filePaths) == 0 {
		return fmt.Errorf("no files found")
	}

	if len(filePaths) != len(fileSizes) || len(filePaths) != len(fileEncrypted) {
		return fmt.Errorf("mismatched input arrays")
	}

	fmt.Println()
	fmt.Printf("%s %s ", successStyle.Render("✓"), boldStyle.Render(fmt.Sprintf("Found %d file(s):", len(filePaths))))
	fmt.Println()

	tableInfo := table.New().Headers("No", "Name", "Size", "Status").Border(lipgloss.NormalBorder()).BorderStyle(boldStyle)
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

		tableInfo = tableInfo.Row(no, name, size, status)
	}

	fmt.Println(tableInfo)
	fmt.Println()

	return nil
}

func ShowSuccessInfo(mode types.ProcessorMode, destPath string) {
	action := "encrypted"
	if mode == types.ModeDecrypt {
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
