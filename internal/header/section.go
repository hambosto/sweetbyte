// Package header provides functionality for handling file headers,
// including serialization and deserialization of metadata.
package header

import (
	"bytes"
	"fmt"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/encoding"
	"github.com/hambosto/sweetbyte/internal/utils"
)

// SectionType defines the different kinds of sections within the header.
type SectionType string

const (
	// SectionMagic identifies the magic bytes section.
	SectionMagic SectionType = "magic"
	// SectionSalt identifies the salt section used in key derivation.
	SectionSalt SectionType = "salt"
	// SectionHeaderData identifies the core header metadata section.
	SectionHeaderData SectionType = "header_data"
	// SectionMAC identifies the message authentication code section.
	SectionMAC SectionType = "mac"
)

// SectionOrder defines the fixed order in which header sections are processed.
// This is crucial for consistent serialization and deserialization.
var SectionOrder = []SectionType{SectionMagic, SectionSalt, SectionHeaderData, SectionMAC}

// EncodedSection represents a Reed-Solomon encoded data section.
// It holds the encoded data and its length.
type EncodedSection struct {
	Data   []byte // The Reed-Solomon encoded data.
	Length uint32 // The length of the encoded data.
}

// SectionEncoder handles the Reed-Solomon encoding and decoding of header sections.
// It wraps an underlying encoder from the encoding package.
type SectionEncoder struct {
	encoder encoding.Encoder
}

// NewSectionEncoder creates a new SectionEncoder with the configured number of data and parity shards.
func NewSectionEncoder() (*SectionEncoder, error) {
	encoder, err := encoding.NewEncoder(config.DataShards, config.ParityShards)
	if err != nil {
		return nil, fmt.Errorf("failed to create reed-solomon encoder: %w", err)
	}
	return &SectionEncoder{encoder: encoder}, nil
}

// EncodeSection encodes a data section using Reed-Solomon error correction.
func (se *SectionEncoder) EncodeSection(data []byte) (*EncodedSection, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data cannot be empty")
	}

	// Perform Reed-Solomon encoding.
	encoded, err := se.encoder.Encode(data)
	if err != nil {
		return nil, fmt.Errorf("failed to encode data: %w", err)
	}

	return &EncodedSection{
		Data:   encoded,
		Length: uint32(len(encoded)),
	}, nil
}

// DecodeSection decodes a Reed-Solomon encoded section, correcting any errors if possible.
func (se *SectionEncoder) DecodeSection(section *EncodedSection) ([]byte, error) {
	if section == nil || len(section.Data) == 0 {
		return nil, fmt.Errorf("invalid encoded section")
	}

	// Perform Reed-Solomon decoding.
	decoded, err := se.encoder.Decode(section.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode data: %w", err)
	}

	return decoded, nil
}

// EncodeLengthPrefix encodes a 32-bit length value into a Reed-Solomon protected section.
// This is used for the metadata that describes the length of other sections.
func (se *SectionEncoder) EncodeLengthPrefix(length uint32) (*EncodedSection, error) {
	lengthBytes := utils.ToBytes(length)
	return se.EncodeSection(lengthBytes)
}

// DecodeLengthPrefix decodes a 32-bit length value from a Reed-Solomon protected section.
func (se *SectionEncoder) DecodeLengthPrefix(section *EncodedSection) (uint32, error) {
	// Decode the section to get the raw length bytes.
	decoded, err := se.DecodeSection(section)
	if err != nil {
		return 0, err
	}

	if len(decoded) < 4 {
		return 0, fmt.Errorf("invalid length prefix size")
	}

	// Convert the first 4 bytes back to a uint32.
	return utils.FromBytes[uint32](decoded[:4]), nil
}

// VerifyMagic checks if the provided byte slice matches the expected magic bytes.
func VerifyMagic(magic []byte) bool {
	return bytes.Equal(magic, utils.ToBytes(MagicBytes))
}
