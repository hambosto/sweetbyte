// Package options provides the application's options.
package options

// ProcessorMode defines the processing mode.
type ProcessorMode string

const (
	// ModeEncrypt is the encryption mode.
	ModeEncrypt ProcessorMode = "Encrypt"
	// ModeDecrypt is the decryption mode.
	ModeDecrypt ProcessorMode = "Decrypt"
)

// DeleteOption defines the file deletion option.
type DeleteOption string

const (
	// DeleteStandard is the standard deletion option.
	DeleteStandard DeleteOption = "Normal Delete (faster, but recoverable)"
	// DeleteSecure is the secure deletion option.
	DeleteSecure DeleteOption = "Secure Delete (slower, but unrecoverable)"
)
