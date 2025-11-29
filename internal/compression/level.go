package compression

type Level int

const (
	LevelNoCompression Level = iota
	LevelBestSpeed
	LevelDefaultCompression
	LevelBestCompression
)
