// Package options defines the different modes and options for the SweetByte application.
package options

// Processing defines the type of processing to be performed.
// It can be either encryption or decryption.
type Processing int

const (
	// Encryption represents the encryption processing type.
	Encryption Processing = iota
	// Decryption represents the decryption processing type.
	Decryption
)

// String returns the string representation of the Processing type.
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
