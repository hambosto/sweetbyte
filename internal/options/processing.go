// Package options provides the application's options.
package options

// Processing defines the processing type.
type Processing int

const (
	// Encryption is the encryption processing type.
	Encryption Processing = iota
	// Decryption is the decryption processing type.
	Decryption
)

// String returns the string representation of the processing type.
func (p Processing) String() string {
	switch p {
	case Encryption:
		return "Encrypting..."
	case Decryption:
		return "Decrypting..."
	default:
		return "Processing..."
	}
}
