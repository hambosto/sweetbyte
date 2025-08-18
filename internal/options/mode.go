// Package options defines the different modes and options for the SweetByte application.
package options

// ProcessorMode defines the mode of operation for the processor.
// It can be either encryption or decryption.
type ProcessorMode string

const (
	// ModeEncrypt represents the encryption mode.
	ModeEncrypt ProcessorMode = "Encrypt"
	// ModeDecrypt represents the decryption mode.
	ModeDecrypt ProcessorMode = "Decrypt"
)

// DeleteOption defines the type of delete operation to be performed.
type DeleteOption string

const (
	// DeleteStandard represents a standard delete operation.
	// This is faster but the data may be recoverable.
	DeleteStandard DeleteOption = "Normal Delete (faster, but recoverable)"
	// DeleteSecure represents a secure delete operation.
	// This is slower but the data is unrecoverable.
	DeleteSecure DeleteOption = "Secure Delete (slower, but unrecoverable)"
)
