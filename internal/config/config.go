// Package config provides application-wide constants and configuration parameters.
// These constants define default values, cryptographic sizes, file extensions, and
// exclusion lists for various operations within the SweetByte application.
package config

const (
	// AppName is the name of the SweetByte application.
	AppName = "SweetByte"
	// AppVersion is the current version of the application.
	AppVersion = "1.0"
	// FileExtension is the default file extension for encrypted SweetByte files.
	FileExtension = ".swb"
)

const (
	// DefaultChunkSize specifies the default size of data chunks processed in streaming operations (1 MB).
	DefaultChunkSize = 1 * 1024 * 1024
	// MaxConcurrency defines the maximum number of concurrent goroutines used for parallel processing.
	MaxConcurrency = 8
	// OverwritePasses specifies the number of times a file's content is overwritten during secure deletion.
	OverwritePasses = 3
)

const (
	// SaltSize is the length of the cryptographic salt used in key derivation (e.g., Argon2id).
	SaltSize = 32
	// MasterKeySize is the total length of the derived master key used for dual-layer encryption.
	MasterKeySize = 64
	// EncryptionKeySize is the size of individual encryption keys (e.g., for AES-256 and XChaCha20).
	EncryptionKeySize = 32
)

var (
	// ExcludedDirs is a list of directory names that should be skipped during file scanning.
	// This prevents processing of sensitive system directories or large dependency folders.
	ExcludedDirs = []string{
		"vendor/", "node_modules/", ".git", ".github",
		".vscode/", "build/", "dist/", "target/",
		".config", ".local", ".cache", ".ssh",
	}

	// ExcludedExts is a list of file extensions that should be skipped during file scanning.
	// This prevents processing of executable binaries, development files, or other non-user data.
	ExcludedExts = []string{
		".go", "go.mod", "go.sum", ".nix", ".gitignore",
		".exe", ".dll", ".so", ".dylib",
	}
)

const (
	// ChunkHeaderSize is the size of the length prefix for each data chunk in the encrypted file format.
	ChunkHeaderSize = 4
)

const (
	// DataShards defines the number of data shards for Reed-Solomon encoding.
	DataShards = 4
	// ParityShards defines the number of parity shards for Reed-Solomon encoding,
	// providing redundancy for error correction.
	ParityShards = 10
)

const (
	// PaddingSize is the block size used for PKCS7 padding.
	PaddingSize = 16
)
