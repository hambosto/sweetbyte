package options

// ProcessorMode represents the operation type for file processing.
type ProcessorMode string

const (
	// ModeEncrypt indicates files should be encrypted.
	ModeEncrypt ProcessorMode = "Encrypt"
	// ModeDecrypt indicates files should be decrypted.
	ModeDecrypt ProcessorMode = "Decrypt"
)

// DeleteOption represents different file deletion methods.
type DeleteOption string

const (
	// DeleteStandard performs normal file deletion (faster, but recoverable).
	DeleteStandard DeleteOption = "Normal Delete (faster, but recoverable)"
	// DeleteSecure performs secure file deletion (slower, but unrecoverable).
	DeleteSecure DeleteOption = "Secure Delete (slower, but unrecoverable)"
)
