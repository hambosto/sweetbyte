package utils

import (
	"encoding/binary"
)

// ToBytes converts a fixed-size value to its big-endian byte representation.
// It supports uint16, uint32, and uint64 types.
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

// FromBytes converts a byte slice to an unsigned integer type.
// It supports uint16, uint32, and uint64.
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
