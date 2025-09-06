// Package ui provides components for the user interface of the SweetByte application.
package ui

import (
	"github.com/schollz/progressbar/v3"
)

// ProgressBar defines the interface for a progress bar.
type ProgressBar interface {
	Add(size int64) error
}

// progressBar is a wrapper around the progressbar library.
type progressBar struct {
	bar         *progressbar.ProgressBar
	description string
}

// NewProgressBar creates a new ProgressBar instance.
func NewProgressBar(totalSize int64, description string) ProgressBar {
	// Initialize a new progress bar with the given options.
	bar := progressbar.NewOptions64(
		totalSize,
		progressbar.OptionSetDescription(description),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowCount(),
		progressbar.OptionFullWidth(),
		progressbar.OptionShowBytes(true),
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
