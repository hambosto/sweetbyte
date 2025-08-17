package config

const (
	AppName		= "SweetByte"
	AppVersion	= "1.0"
	FileExtension	= ".swb"
)

const (
	DefaultChunkSize	= 1 * 1024 * 1024
	MaxConcurrency		= 8
	OverwritePasses		= 3
)

const (
	SaltSize		= 32
	MasterKeySize		= 64
	EncryptionKeySize	= 32
)

var (
	ExcludedDirs	= []string{
		"vendor/", "node_modules/", ".git", ".github",
		".vscode/", "build/", "dist/", "target/",
		".config", ".local", ".cache", ".ssh",
	}

	ExcludedExts	= []string{
		".go", "go.mod", "go.sum", ".nix", ".gitignore",
		".exe", ".dll", ".so", ".dylib",
	}
)

const (
	ChunkHeaderSize = 4
)

const (
	DataShards	= 4
	ParityShards	= 10
)

const (
	PaddingSize = 16
)
