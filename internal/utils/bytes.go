// Package utils provides utility functions for the SweetByte application.
package utils

import (
	"encoding/binary"
	"unsafe"
)

// UnsignedInt is a type constraint that allows only unsigned integer types
// (uint16, uint32, uint64) to be used with the generic conversion functions.
type UnsignedInt interface {
	uint16 | uint32 | uint64
}

// ToBytes converts an unsigned integer to a byte slice using big-endian encoding.
//
// The function accepts uint16, uint32, or uint64 values and returns their
// binary representation as a byte slice. The byte order is big-endian (most
// significant byte first).
func ToBytes[T UnsignedInt](v T) []byte {
	size := int(unsafe.Sizeof(v))
	buffer := make([]byte, size)

	switch size {
	case 2: // uint16
		binary.BigEndian.PutUint16(buffer, uint16(v))
	case 4: // uint32
		binary.BigEndian.PutUint32(buffer, uint32(v))
	case 8: // uint64
		binary.BigEndian.PutUint64(buffer, uint64(v))
	}

	return buffer
}

// FromBytes converts a byte slice back to the specified unsigned integer type
// using big-endian decoding.
//
// The function takes a byte slice and converts it to the specified unsigned
// integer type (uint16, uint32, or uint64). The byte slice must have the
// correct length for the target type:
//   - uint16 requires exactly 2 bytes
//   - uint32 requires exactly 4 bytes
//   - uint64 requires exactly 8 bytes
//
// The function will panic if the byte slice length doesn't match the expected
// size for the target type.
func FromBytes[T UnsignedInt](b []byte) T {
	var zero T
	expectedSize := int(unsafe.Sizeof(zero))

	switch expectedSize {
	case 2: // uint16
		return T(binary.BigEndian.Uint16(b))
	case 4: // uint32
		return T(binary.BigEndian.Uint32(b))
	case 8: // uint64
		return T(binary.BigEndian.Uint64(b))
	default:
		// This should never happen due to the type constraint
		panic("unsupported type")
	}
}
