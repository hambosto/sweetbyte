package options

// Processing represents the high-level operation applied to a data stream.
//
// It is used across streaming, CLI, and UI layers to:
//   - Select the correct transformation pipeline (encryption or decryption)
//   - Drive user-facing status text (see Processing.String)
//   - Configure chunk reader/writer behavior (e.g., length prefixing on encryption)
//
// Values are stable and safe to persist for internal configuration. Do not
// reorder existing values; append new values at the end if additional
// processing modes are introduced in the future.
type Processing int

const (
	// Encryption indicates data should be encrypted.
	Encryption Processing = iota
	// Decryption indicates data should be decrypted.
	Decryption
)

// String returns a concise user-facing status message for the processing
// operation. This is shown in progress bars and logging to indicate the
// current action being performed.
func (p Processing) String() string {
	switch p {
	case Encryption:
		return "Encrypting..."
	case Decryption:
		return "Decrypting..."
	default:
		// Keep generic fallback for forward compatibility if unknown values
		// are received (e.g., from persisted configs created by newer builds).
		return "Processing..."
	}
}
