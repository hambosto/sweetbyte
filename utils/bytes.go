package utils

import (
	"encoding/binary"

	"github.com/ccoveille/go-safecast/v2"
)

func ToBytes[T safecast.Number, V safecast.Number](v V) []byte {
	converted := safecast.MustConvert[T](v)

	var zero T
	switch any(zero).(type) {
	case uint16:
		b := make([]byte, 2)
		binary.BigEndian.PutUint16(b, uint16(converted))
		return b
	case uint32:
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, uint32(converted))
		return b
	case uint64:
		b := make([]byte, 8)
		binary.BigEndian.PutUint64(b, uint64(converted))
		return b
	default:
		panic("unsupported type")
	}
}

func FromBytes[T safecast.Number](b []byte) T {
	var zero T

	switch any(zero).(type) {
	case uint16:
		if len(b) < 2 {
			return zero
		}
		return T(binary.BigEndian.Uint16(b))
	case uint32:
		if len(b) < 4 {
			return zero
		}
		return T(binary.BigEndian.Uint32(b))
	case uint64:
		if len(b) < 8 {
			return zero
		}
		return T(binary.BigEndian.Uint64(b))
	default:
		panic("unsupported type")
	}
}
