package header

import (
	"bytes"
	"fmt"

	"github.com/hambosto/sweetbyte/internal/config"
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

// EncodedSection represents a Reed-Solomon encoded data section.
type EncodedSection struct {
	Data   []byte
	Length uint32
}

type SectionEncoder struct {
	encoder encoding.Encoder
}

func NewSectionEncoder() (*SectionEncoder, error) {
	encoder, err := encoding.NewEncoder(config.DataShards, config.ParityShards)
	if err != nil {
		return nil, fmt.Errorf("failed to create reed-solomon encoder: %w", err)
	}
	return &SectionEncoder{encoder: encoder}, nil
}

// EncodeSection encodes a data section with Reed-Solomon.
func (se *SectionEncoder) EncodeSection(data []byte) (*EncodedSection, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data cannot be empty")
	}

	encoded, err := se.encoder.Encode(data)
	if err != nil {
		return nil, fmt.Errorf("failed to encode data: %w", err)
	}

	return &EncodedSection{
		Data:   encoded,
		Length: uint32(len(encoded)),
	}, nil
}

// DecodeSection decodes a Reed-Solomon encoded section.
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

// EncodeLengthPrefix encodes a length value for section metadata.
func (se *SectionEncoder) EncodeLengthPrefix(length uint32) (*EncodedSection, error) {
	lengthBytes := utils.ToBytes(length)
	return se.EncodeSection(lengthBytes)
}

// DecodeLengthPrefix decodes a length value from section metadata.
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
	return bytes.Equal(magic, []byte(MagicBytes))
}
