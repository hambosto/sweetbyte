// Package utils provides utility functions for the SweetByte application.
package utils

import (
	"fmt"
)

// FormatBytes converts a byte count into a human-readable string.
// It uses binary prefixes (KiB, MiB, etc.) for formatting.
func FormatBytes(bytes int64) string {
	// If the byte count is 0, return "0 B".
	if bytes == 0 {
		return "0 B"
	}

	// The base unit for conversion (1024 bytes).
	const unit = 1024
	// If the byte count is less than the unit, return it in bytes.
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}

	// Initialize the divisor and exponent for calculation.
	div, exp := int64(unit), 0
	// Loop to find the correct unit (KiB, MiB, etc.).
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}

	// Return the formatted string with the appropriate unit.
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}
