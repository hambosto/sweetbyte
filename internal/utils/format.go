// Package utils provides a collection of small, reusable utility functions
// that support various parts of the SweetByte application, such as data formatting.
package utils

import (
	"fmt"
)

// FormatBytes converts a byte count into a human-readable string format (e.g., 10 MB, 2.5 GB).
// It automatically scales the unit (B, KB, MB, GB, TB, PB, EB) based on the size.
func FormatBytes(bytes int64) string {
	if bytes == 0 { // Handle the special case of zero bytes.
		return "0 B"
	}

	const unit = 1024 // Define the unit for byte conversion (1024 for binary units).
	if bytes < unit { // If the size is less than 1 KB, display in Bytes.
		return fmt.Sprintf("%d B", bytes)
	}

	// Iterate to find the most appropriate unit (KB, MB, GB, etc.).
	div, exp := int64(unit), 0                    // Initialize divisor and exponent for unit calculation.
	for n := bytes / unit; n >= unit; n /= unit { // Loop while the current value is greater than or equal to the unit.
		div *= unit // Increase the divisor (e.g., from KB to MB).
		exp++       // Increment the exponent to select the correct unit suffix.
	}

	// Format the bytes with one decimal place and the appropriate unit suffix.
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
