// Package options defines various operational modes and settings for the SweetByte application.
// These types and constants control how files are processed and how certain operations are performed.
package options

// ProcessorMode defines the main operation modes for the SweetByte application.
type ProcessorMode string

const (
	// ModeEncrypt represents the encryption operation mode.
	ModeEncrypt ProcessorMode = "Encrypt"
	// ModeDecrypt represents the decryption operation mode.
	ModeDecrypt ProcessorMode = "Decrypt"
)

// DeleteOption defines the available methods for deleting files.
type DeleteOption string

const (
	// DeleteStandard specifies a fast but potentially recoverable file deletion.
	DeleteStandard DeleteOption = "Normal Delete (faster, but recoverable)"
	// DeleteSecure specifies a slower but cryptographically secure file deletion.
	DeleteSecure DeleteOption = "Secure Delete (slower, but unrecoverable)"
)
