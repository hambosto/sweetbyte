package options

// Processing represents the stream processing operation type.
type Processing int

const (
	// Encryption indicates data should be encrypted.
	Encryption Processing = iota
	// Decryption indicates data should be decrypted.
	Decryption
)

// String returns a user-friendly status message for the processing operation.
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
