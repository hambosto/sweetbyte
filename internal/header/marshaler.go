package header

import (
	"fmt"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/utils"
)

type Marshaler struct {
	header       *Header
	serializer   *Serializer
	encoder      *SectionEncoder
	macProcessor *MACProcessor
}

func NewMarshaler(header *Header) *Marshaler {
	return &Marshaler{
		header:       header,
		serializer:   NewSerializer(),
		encoder:      NewSectionEncoder(header.encoder),
		macProcessor: NewMACProcessor(),
	}
}

func (m *Marshaler) Marshal(salt, key []byte) ([]byte, error) {
	if err := m.validateInputs(salt, key); err != nil {
		return nil, err
	}

	magic := []byte(MagicBytes)
	headerData := m.serializer.Serialize(m.header)
	mac, err := m.macProcessor.ComputeMAC(key, magic, salt, headerData)
	if err != nil {
		return nil, fmt.Errorf("failed to compute MAC: %w", err)
	}

	sections, err := m.encodeSections(magic, salt, headerData, mac)
	if err != nil {
		return nil, err
	}

	lengthSections, err := m.encodeLengthPrefixes(sections)
	if err != nil {
		return nil, err
	}

	lengthsHeader := m.buildLengthsHeader(lengthSections)
	return m.assembleEncodedHeader(lengthsHeader, lengthSections, sections), nil
}

func (m *Marshaler) validateInputs(salt, key []byte) error {
	if err := m.header.Validate(); err != nil {
		return fmt.Errorf("header validation failed: %w", err)
	}
	if len(salt) != config.SaltSize {
		return fmt.Errorf("invalid salt size: expected %d, got %d", config.SaltSize, len(salt))
	}
	if len(key) == 0 {
		return fmt.Errorf("key cannot be empty")
	}
	return nil
}

func (m *Marshaler) encodeSections(magic, salt, headerData, mac []byte) (map[SectionType]*EncodedSection, error) {
	sections := make(map[SectionType]*EncodedSection)
	var err error

	if sections[SectionMagic], err = m.encoder.EncodeSection(magic); err != nil {
		return nil, fmt.Errorf("failed to encode magic: %w", err)
	}
	if sections[SectionSalt], err = m.encoder.EncodeSection(salt); err != nil {
		return nil, fmt.Errorf("failed to encode salt: %w", err)
	}
	if sections[SectionHeaderData], err = m.encoder.EncodeSection(headerData); err != nil {
		return nil, fmt.Errorf("failed to encode header data: %w", err)
	}
	if sections[SectionMAC], err = m.encoder.EncodeSection(mac); err != nil {
		return nil, fmt.Errorf("failed to encode MAC: %w", err)
	}

	return sections, nil
}

func (m *Marshaler) encodeLengthPrefixes(sections map[SectionType]*EncodedSection) (map[SectionType]*EncodedSection, error) {
	lengthSections := make(map[SectionType]*EncodedSection)
	var err error

	for sectionType, section := range sections {
		if lengthSections[sectionType], err = m.encoder.EncodeLengthPrefix(section.Length); err != nil {
			return nil, fmt.Errorf("failed to encode length for %s: %w", sectionType, err)
		}
	}

	return lengthSections, nil
}

func (m *Marshaler) buildLengthsHeader(lengthSections map[SectionType]*EncodedSection) []byte {
	lengthsHeader := make([]byte, 0, 16)
	lengthsHeader = append(lengthsHeader, utils.ToBytes(lengthSections[SectionMagic].Length)...)
	lengthsHeader = append(lengthsHeader, utils.ToBytes(lengthSections[SectionSalt].Length)...)
	lengthsHeader = append(lengthsHeader, utils.ToBytes(lengthSections[SectionHeaderData].Length)...)
	lengthsHeader = append(lengthsHeader, utils.ToBytes(lengthSections[SectionMAC].Length)...)
	return lengthsHeader
}

func (m *Marshaler) assembleEncodedHeader(lengthsHeader []byte, lengthSections map[SectionType]*EncodedSection, sections map[SectionType]*EncodedSection) []byte {
	var result []byte
	result = append(result, lengthsHeader...)
	result = append(result, lengthSections[SectionMagic].Data...)
	result = append(result, lengthSections[SectionSalt].Data...)
	result = append(result, lengthSections[SectionHeaderData].Data...)
	result = append(result, lengthSections[SectionMAC].Data...)
	result = append(result, sections[SectionMagic].Data...)
	result = append(result, sections[SectionSalt].Data...)
	result = append(result, sections[SectionHeaderData].Data...)
	result = append(result, sections[SectionMAC].Data...)
	return result
}
