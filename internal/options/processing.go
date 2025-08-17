// Package options defines various operational modes and settings for the SweetByte application.
// These types and constants control how files are processed and how certain operations are performed.
package options

// Processing defines the type of data processing operation to be performed.
type Processing int

const (
	// Encryption indicates that the operation is for encrypting data.
	Encryption Processing = iota
	// Decryption indicates that the operation is for decrypting data.
	Decryption
)

// String returns a human-readable string representation of the Processing mode.
func (p Processing) String() string {
	switch p { // Use a switch statement to return the appropriate string for each processing mode.
	case Encryption:
		return "Encrypting..."
	case Decryption:
		return "Decrypting..."
	default:
		return "Processing..." // Default string for unknown or unhandled processing modes.
	}
}
