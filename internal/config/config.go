package config

// Application Configuration provides general application information.
const (
	// AppName is the name of the application.
	AppName = "SweetByte"
	// AppVersion is the current version of the application.
	AppVersion = "1.0"
	// FileExtension is the default extension for encrypted files.
	FileExtension = ".swb"
)

// Processing Configuration defines parameters for file processing.
const (
	// DefaultChunkSize is the size of data chunks processed in memory (1MB).
	DefaultChunkSize = 1 * 1024 * 1024
	// MaxConcurrency is the maximum number of concurrent workers for encryption/decryption.
	MaxConcurrency = 8
	// OverwritePasses is the number of times a file is overwritten during secure deletion.
	OverwritePasses = 3
)

// Cryptographic Configuration specifies parameters for cryptographic operations.
const (
	// SaltSize is the size of the salt used in Argon2id key derivation (32 bytes).
	SaltSize = 32
	// MasterKeySize is the total size of the master key derived from the password (64 bytes).
	// This key is split to provide separate keys for the two ciphers.
	MasterKeySize = 64
	// EncryptionKeySize is the size of the key for a single cipher (32 bytes for AES-256).
	EncryptionKeySize = 32
)

// File Processing Configuration defines which files and directories to exclude
// when searching for files in interactive mode.
var (
	// ExcludedDirs is a list of directory names to ignore.
	ExcludedDirs = []string{
		"vendor/", "node_modules/", ".git", ".github",
		".vscode/", "build/", "dist/", "target/",
		".config", ".local", ".cache", ".ssh",
	}

	// ExcludedExts is a list of file extensions to ignore.
	ExcludedExts = []string{
		".go", "go.mod", "go.sum", ".nix", ".gitignore",
		".exe", ".dll", ".so", ".dylib",
	}
)

// Stream Processing Constants defines parameters for the streaming protocol.
const (
	// ChunkHeaderSize is the size of the header preceding each chunk,
	// which stores the length of the chunk.
	ChunkHeaderSize = 4
)

// Reed-Solomon Encoding Configuration specifies the parameters for error correction.
const (
	// DataShards is the number of data shards the original data is split into.
	DataShards = 4
	// ParityShards is the number of parity shards added for error correction.
	ParityShards = 10
)

// Padding Configuration defines the block size for PKCS7 padding.
const (
	// PaddingSize is the block size to which data is padded before encryption.
	PaddingSize = 16
)
