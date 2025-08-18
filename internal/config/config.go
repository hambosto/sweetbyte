// Package config provides configuration constants for the SweetByte application.
package config

const (
	// AppName is the name of the application.
	AppName = "SweetByte"
	// AppVersion is the version of the application.
	AppVersion = "1.0"
	// FileExtension is the file extension for encrypted files.
	FileExtension = ".swb"
)

const (
	// DefaultChunkSize is the default size of chunks for streaming operations.
	DefaultChunkSize = 1 * 1024 * 1024
	// MaxConcurrency is the maximum number of concurrent operations.
	MaxConcurrency = 8
	// OverwritePasses is the number of passes for secure file deletion.
	OverwritePasses = 3
)

const (
	// SaltSize is the size of the salt used for key derivation.
	SaltSize = 32
	// MasterKeySize is the size of the master key.
	MasterKeySize = 64
	// EncryptionKeySize is the size of the encryption key.
	EncryptionKeySize = 32
)

var (
	// ExcludedDirs is a list of directories to exclude when searching for files.
	ExcludedDirs = []string{
		"vendor/", "node_modules/", ".git", ".github",
		".vscode/", "build/", "dist/", "target/",
		".config", ".local", ".cache", ".ssh",
	}

	// ExcludedExts is a list of file extensions to exclude when searching for files.
	ExcludedExts = []string{
		".go", "go.mod", "go.sum", ".nix", ".gitignore",
		".exe", ".dll", ".so", ".dylib",
	}
)

const (
	// ChunkHeaderSize is the size of the header for each chunk.
	ChunkHeaderSize = 4
)

const (
	// DataShards is the number of data shards for Reed-Solomon encoding.
	DataShards = 4
	// ParityShards is the number of parity shards for Reed-Solomon encoding.
	ParityShards = 10
)

const (
	// PaddingSize is the size of the padding for the header.
	PaddingSize = 16
)
