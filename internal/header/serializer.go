package header

import (
	"fmt"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/utils"
)

type Serializer struct {
	header  *Header
	encoder *SectionEncoder
}

func NewSerializer(header *Header) *Serializer {
	return &Serializer{
		header:  header,
		encoder: NewSectionEncoder(header.encoder),
	}
}

func (s *Serializer) Marshal(salt, key []byte) ([]byte, error) {
	if err := s.validateInputs(salt, key); err != nil {
		return nil, err
	}

	magic := []byte(MagicBytes)
	headerData := s.serialize(s.header)
	mac, err := ComputeMAC(key, magic, salt, headerData)
	if err != nil {
		return nil, fmt.Errorf("failed to compute MAC: %w", err)
	}

	sections, err := s.encodeSections(magic, salt, headerData, mac)
	if err != nil {
		return nil, err
	}

	lengthSections, err := s.encodeLengthPrefixes(sections)
	if err != nil {
		return nil, err
	}

	lengthsHeader := s.buildLengthsHeader(lengthSections)
	return s.assembleEncodedHeader(lengthsHeader, lengthSections, sections), nil
}

func (m *Serializer) validateInputs(salt, key []byte) error {
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

func (m *Serializer) encodeSections(magic, salt, headerData, mac []byte) (map[SectionType]*EncodedSection, error) {
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

func (m *Serializer) encodeLengthPrefixes(sections map[SectionType]*EncodedSection) (map[SectionType]*EncodedSection, error) {
	lengthSections := make(map[SectionType]*EncodedSection)
	var err error

	for sectionType, section := range sections {
		if lengthSections[sectionType], err = m.encoder.EncodeLengthPrefix(section.Length); err != nil {
			return nil, fmt.Errorf("failed to encode length for %s: %w", sectionType, err)
		}
	}

	return lengthSections, nil
}

func (m *Serializer) buildLengthsHeader(lengthSections map[SectionType]*EncodedSection) []byte {
	lengthsHeader := make([]byte, 0, 16)
	lengthsHeader = append(lengthsHeader, utils.ToBytes(lengthSections[SectionMagic].Length)...)
	lengthsHeader = append(lengthsHeader, utils.ToBytes(lengthSections[SectionSalt].Length)...)
	lengthsHeader = append(lengthsHeader, utils.ToBytes(lengthSections[SectionHeaderData].Length)...)
	lengthsHeader = append(lengthsHeader, utils.ToBytes(lengthSections[SectionMAC].Length)...)
	return lengthsHeader
}

func (m *Serializer) assembleEncodedHeader(
	lengthsHeader []byte,
	lengthSections map[SectionType]*EncodedSection,
	sections map[SectionType]*EncodedSection,
) []byte {
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

func (s *Serializer) serialize(h *Header) []byte {
	data := make([]byte, 0, HeaderDataSize)
	data = append(data, utils.ToBytes(h.Version)...)
	data = append(data, utils.ToBytes(h.Flags)...)
	data = append(data, utils.ToBytes(h.OriginalSize)...)
	return data
}
