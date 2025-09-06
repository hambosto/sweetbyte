// Package utils provides utility functions.
package utils

import (
	"encoding/binary"
)

// ToBytes converts a uint16, uint32, or uint64 to a byte slice.
func ToBytes(v any) []byte {
	switch val := v.(type) {
	case uint16:
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, val)
		return b
	case uint32:
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, val)
		return b
	case uint64:
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, val)
		return b
	}
	return nil
}

// FromBytes converts a byte slice to a uint16, uint32, or uint64.
func FromBytes[T ~uint16 | ~uint32 | ~uint64](b []byte) T {
	var zero T
	switch any(zero).(type) {
	case uint16:
		return T(binary.BigEndian.Uint16(b))
	case uint32:
		return T(binary.BigEndian.Uint32(b))
	case uint64:
		return T(binary.BigEndian.Uint64(b))
	}
	return zero
}
