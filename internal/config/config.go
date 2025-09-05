// Package config provides configuration constants for the SweetByte application.
package config

const (
	// AppName is the name of the application.
	AppName = "SweetByte"

	// AppVersion is the current version of the application.
	AppVersion = "1.0"

	// FileExtension is the file extension applied to encrypted files.
	FileExtension = ".swb"
)

const (
	// DefaultChunkSize is the default size (in bytes) of chunks used
	// during streaming read/write operations (e.g., encryption, decryption).
	DefaultChunkSize = 1 * 1024 * 1024 // 1 MB

	// OverwritePasses is the number of overwrite passes used when securely
	// deleting files to reduce the chance of data recovery.
	OverwritePasses = 3

	// PasswordMinLen defines the minimum required length for user passwords.
	PasswordMinLen = 8
)

const (
	// SaltSize is the number of random bytes used as a salt in key derivation.
	SaltSize = 32

	// MasterKeySize is the size (in bytes) of the master key derived from the password.
	MasterKeySize = 64

	// EncryptionKeySize is the size (in bytes) of the encryption key used for symmetric encryption.
	EncryptionKeySize = 32
)

var (
	// ExcludedDirs lists directories that should be skipped when scanning
	// for files to encrypt or process. These are typically system, cache,
	// or development-related directories.
	ExcludedDirs = []string{
		"vendor/", "node_modules/", ".git", ".github",
		".vscode/", "build/", "dist/", "target/",
		".config", ".local", ".cache", ".ssh",
	}

	// ExcludedExts lists file extensions that should be skipped when scanning
	// for files to encrypt. This avoids encrypting executables, system files,
	// or project configuration files.
	ExcludedExts = []string{
		".go", "go.mod", "go.sum", ".nix", ".gitignore",
		".exe", ".dll", ".so", ".dylib",
	}
)

const (
	// DataShards is the number of data shards used in Reed-Solomon
	// erasure coding for redundancy and reliability.
	DataShards = 4

	// ParityShards is the number of parity shards used in Reed-Solomon
	// erasure coding to allow data recovery in case of corruption or loss.
	ParityShards = 10
)

const (
	// PaddingSize is the fixed number of padding bytes applied to the file
	// header to ensure alignment and obscure actual header size.
	PaddingSize = 16
)
