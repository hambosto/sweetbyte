// Package utils provides utility functions for the SweetByte application.
package utils

import (
	"crypto/subtle"
)

// SecureCompare performs a constant-time comparison of two byte slices.
func SecureCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}
