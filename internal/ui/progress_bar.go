// Package ui provides user interface components and utilities for the SweetByte application.
// This includes terminal manipulation, interactive prompts, and progress bar displays,
// enhancing the user experience in both CLI and interactive modes.
package ui

import (
	"github.com/schollz/progressbar/v3"
)

// ProgressBar wraps the progressbar.ProgressBar library to provide visual feedback
// during long-running operations like file encryption and decryption.
type ProgressBar struct {
	bar         *progressbar.ProgressBar // The underlying progress bar instance.
	description string                   // A description of the operation being tracked.
}

// NewProgressBar creates and returns a new ProgressBar instance.
// It initializes the underlying progressbar.ProgressBar with various options
// to customize its appearance and behavior.
func NewProgressBar(totalSize int64, description string) *ProgressBar {
	bar := progressbar.NewOptions64( // Create a new progress bar with a total size.
		totalSize, // Total number of units (bytes) for the progress bar.
		progressbar.OptionSetDescription(description),        // Set the description text for the progress bar.
		progressbar.OptionEnableColorCodes(true),             // Enable color codes for better visual presentation.
		progressbar.OptionShowCount(),                        // Show the current count of processed units.
		progressbar.OptionFullWidth(),                        // Make the progress bar span the full width of the terminal.
		progressbar.OptionShowBytes(true),                    // Display progress in bytes (e.g., 10MB/100MB).
		progressbar.OptionSetTheme(progressbar.ThemeUnicode), // Use Unicode characters for the progress bar theme.
	)

	return &ProgressBar{
		bar:         bar,         // Assign the initialized progress bar.
		description: description, // Store the description.
	}
}

// Add increments the progress bar by the given size.
// It delegates the actual increment logic to the underlying progressbar.ProgressBar.
func (p *ProgressBar) Add(size int64) error {
	return p.bar.Add64(size) // Add the specified size to the progress bar's current value.
}
