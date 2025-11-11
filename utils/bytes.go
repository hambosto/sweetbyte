package utils

import (
	"encoding/binary"
)

var ByteOrder binary.ByteOrder = binary.BigEndian

type UintType interface {
	uint16 | uint32 | uint64
}

func ToBytes[T UintType](v T) []byte {
	switch any(v).(type) {
	case uint16:
		b := make([]byte, 2)
		ByteOrder.PutUint16(b, uint16(any(v).(uint16)))
		return b
	case uint32:
		b := make([]byte, 4)
		ByteOrder.PutUint32(b, uint32(any(v).(uint32)))
		return b
	case uint64:
		b := make([]byte, 8)
		ByteOrder.PutUint64(b, uint64(any(v).(uint64)))
		return b
	}
	return nil
}

func FromBytes[T UintType](b []byte) T {
	var zero T
	switch any(zero).(type) {
	case uint16:
		if len(b) < 2 {
			panic("insufficient bytes for uint16")
		}
		return T(ByteOrder.Uint16(b))
	case uint32:
		if len(b) < 4 {
			panic("insufficient bytes for uint32")
		}
		return T(ByteOrder.Uint32(b))
	case uint64:
		if len(b) < 8 {
			panic("insufficient bytes for uint64")
		}
		return T(ByteOrder.Uint64(b))
	}
	return zero
}
