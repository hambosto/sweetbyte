package bar

import (
	"time"

	"github.com/schollz/progressbar/v3"
)

type ProgressBar struct {
	bar         *progressbar.ProgressBar
	description string
}

func NewProgressBar(totalSize int64, description string) *ProgressBar {
	bar := progressbar.NewOptions64(
		totalSize,
		progressbar.OptionSetDescription(description),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowBytes(true),
		progressbar.OptionShowCount(),
		progressbar.OptionFullWidth(),
		progressbar.OptionThrottle(100*time.Millisecond),
		progressbar.OptionSetTheme(progressbar.Theme{
			BarStart:      "[",
			BarEnd:        "]",
			Saucer:        "●",
			SaucerPadding: "○",
		}),
	)

	return &ProgressBar{
		bar:         bar,
		description: description,
	}
}

func (p *ProgressBar) Add(size int64) error {
	return p.bar.Add64(size)
}
