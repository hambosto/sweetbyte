package ui

import (
	"github.com/schollz/progressbar/v3"
)

type ProgressBar interface {
	Add(size int64) error
}

type progressBar struct {
	bar         *progressbar.ProgressBar
	description string
}

func NewProgressBar(totalSize int64, description string) ProgressBar {
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

func (p *progressBar) Add(size int64) error {
	return p.bar.Add64(size)
}
