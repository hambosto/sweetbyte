package config

// Application Configuration
const (
	AppName       = "SweetByte"
	AppVersion    = "1.0"
	FileExtension = ".swb"
)

// Processing Configuration
const (
	DefaultChunkSize = 1 * 1024 * 1024 // 1MB chunks
	MaxConcurrency   = 8               // Max worker threads
	OverwritePasses  = 3               // Secure deletion passes
)

// Cryptographic Configuration
const (
	SaltSize          = 32 // Argon2id salt size
	MasterKeySize     = 64 // AES-256 key size
	EncryptionKeySize = 32 // AES-256 key size
)

// File Processing Configuration
var (
	ExcludedDirs = []string{
		"vendor/", "node_modules/", ".git", ".github",
		".vscode/", "build/", "dist/", "target/",
		".config", ".local", ".cache", ".ssh",
	}

	ExcludedExts = []string{
		".go", "go.mod", "go.sum", ".nix", ".gitignore",
		".exe", ".dll", ".so", ".dylib",
	}
)

// Stream Processing Constants
const (
	ChunkHeaderSize = 4 // Size of chunk length header in bytes
)

// Reed-Solomon Encoding Configuration
const (
	DataShards   = 4  // Number of data shards
	ParityShards = 10 // Number of parity shards for error correction
)

// Padding Configuration
const (
	PaddingSize = 16 // Block size for padding
)
