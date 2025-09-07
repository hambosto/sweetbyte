// Package ui provides user interface functionalities.
package ui

import (
	"github.com/schollz/progressbar/v3"
)

// ProgressBar defines the interface for a progress bar.
type ProgressBar interface {
	// Add adds the given size to the progress bar.
	Add(size int64) error
}

// progressBar implements the ProgressBar interface.
type progressBar struct {
	bar         *progressbar.ProgressBar
	description string
}

// NewProgressBar creates a new ProgressBar.
func NewProgressBar(totalSize int64, description string) ProgressBar {
	// Create a new progress bar with the given options.
	bar := progressbar.NewOptions64(
		totalSize,
		progressbar.OptionSetDescription(description),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowBytes(true),
		progressbar.OptionClearOnFinish(),
		progressbar.OptionShowCount(),
		progressbar.OptionFullWidth(),
		progressbar.OptionSetTheme(progressbar.ThemeUnicode),
	)

	return &progressBar{
		bar:         bar,
		description: description,
	}
}

// Add adds the given size to the progress bar.
func (p *progressBar) Add(size int64) error {
	return p.bar.Add64(size)
}
