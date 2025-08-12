package types

// CompressionLevel represents compression levels.
type CompressionLevel int

const (
	// LevelNoCompression disables compression.
	LevelNoCompression CompressionLevel = 0
	// LevelBestSpeed provides fastest compression.
	LevelBestSpeed CompressionLevel = 1
	// LevelDefaultCompression provides balanced compression.
	LevelDefaultCompression CompressionLevel = -1
	// LevelBestCompression provides maximum compression.
	LevelBestCompression CompressionLevel = 9
)
