package header

import (
	"fmt"

	"github.com/hambosto/sweetbyte/internal/utils"
)

type Serializer struct{}

func NewSerializer() *Serializer {
	return &Serializer{}
}

func (s *Serializer) Serialize(h *Header) []byte {
	data := make([]byte, 0, HeaderDataSize)
	data = append(data, utils.ToBytes(h.Version)...)
	data = append(data, utils.ToBytes(h.Flags)...)
	data = append(data, utils.ToBytes(h.OriginalSize)...)
	return data
}

func (s *Serializer) Deserialize(h *Header, data []byte) error {
	if len(data) != HeaderDataSize {
		return fmt.Errorf("invalid header data size: expected %d bytes, got %d", HeaderDataSize, len(data))
	}
	h.Version = utils.FromBytes[uint16](data[0:2])
	h.Flags = utils.FromBytes[uint32](data[2:6])
	h.OriginalSize = utils.FromBytes[uint64](data[6:14])
	return nil
}
