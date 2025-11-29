package header

import (
	"bytes"
	"fmt"

	"github.com/ccoveille/go-safecast/v2"
	"github.com/hambosto/sweetbyte/internal/encoding"
	"github.com/hambosto/sweetbyte/internal/utils"
)

type SectionType string

const (
	SectionMagic      SectionType = "magic"
	SectionSalt       SectionType = "salt"
	SectionHeaderData SectionType = "header_data"
	SectionMAC        SectionType = "mac"
)

var SectionOrder = []SectionType{SectionMagic, SectionSalt, SectionHeaderData, SectionMAC}

type EncodedSection struct {
	Data   []byte
	Length uint32
}

type SectionEncoder struct {
	encoder *encoding.Encoding
}

func NewSectionEncoder() (*SectionEncoder, error) {
	encoder, err := encoding.NewEncoding(encoding.DataShards, encoding.ParityShards)
	if err != nil {
		return nil, fmt.Errorf("failed to create reed-solomon encoder: %w", err)
	}
	return &SectionEncoder{encoder: encoder}, nil
}

func (se *SectionEncoder) EncodeSection(data []byte) (*EncodedSection, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data cannot be empty")
	}

	encoded, err := se.encoder.Encode(data)
	if err != nil {
		return nil, fmt.Errorf("failed to encode data: %w", err)
	}

	encodedLen := safecast.MustConvert[uint32](len(encoded))
	return &EncodedSection{
		Data:   encoded,
		Length: encodedLen,
	}, nil
}

func (se *SectionEncoder) DecodeSection(section *EncodedSection) ([]byte, error) {
	if section == nil || len(section.Data) == 0 {
		return nil, fmt.Errorf("invalid encoded section")
	}

	decoded, err := se.encoder.Decode(section.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode data: %w", err)
	}

	return decoded, nil
}

func (se *SectionEncoder) EncodeLengthPrefix(length uint32) (*EncodedSection, error) {
	lengthBytes := utils.ToBytes[uint32](length)
	return se.EncodeSection(lengthBytes)
}

func (se *SectionEncoder) DecodeLengthPrefix(section *EncodedSection) (uint32, error) {
	decoded, err := se.DecodeSection(section)
	if err != nil {
		return 0, err
	}

	if len(decoded) < 4 {
		return 0, fmt.Errorf("invalid length prefix size")
	}

	return utils.FromBytes[uint32](decoded[:4]), nil
}

func VerifyMagic(magic []byte) bool {
	return bytes.Equal(magic, utils.ToBytes[uint32](MagicBytes))
}
