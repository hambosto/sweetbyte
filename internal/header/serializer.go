package header

import (
	"fmt"

	"github.com/hambosto/sweetbyte/internal/derive"
	"github.com/hambosto/sweetbyte/internal/utils"
)

type Serializer struct {
	header  *Header
	encoder *SectionEncoder
}

func NewSerializer(header *Header) (*Serializer, error) {
	encoder, err := NewSectionEncoder()
	if err != nil {
		return nil, fmt.Errorf("failed to create section encoder: %w", err)
	}
	return &Serializer{
		header:  header,
		encoder: encoder,
	}, nil
}

func (s *Serializer) Marshal(salt, key []byte) ([]byte, error) {
	if err := s.validateInputs(salt, key); err != nil {
		return nil, err
	}

	magic := utils.ToBytes[uint32](MagicBytes)
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

func (s *Serializer) validateInputs(salt, key []byte) error {
	if err := s.header.Validate(); err != nil {
		return fmt.Errorf("header validation failed: %w", err)
	}
	if len(salt) != derive.ArgonSaltLen {
		return fmt.Errorf("invalid salt size: expected %d, got %d", derive.ArgonSaltLen, len(salt))
	}
	if len(key) == 0 {
		return fmt.Errorf("key cannot be empty")
	}
	return nil
}

func (s *Serializer) encodeSections(magic, salt, headerData, mac []byte) (map[SectionType]*EncodedSection, error) {
	sections := make(map[SectionType]*EncodedSection)

	var err error
	if sections[SectionMagic], err = s.encoder.EncodeSection(magic); err != nil {
		return nil, fmt.Errorf("failed to encode magic: %w", err)
	}
	if sections[SectionSalt], err = s.encoder.EncodeSection(salt); err != nil {
		return nil, fmt.Errorf("failed to encode salt: %w", err)
	}
	if sections[SectionHeaderData], err = s.encoder.EncodeSection(headerData); err != nil {
		return nil, fmt.Errorf("failed to encode header data: %w", err)
	}
	if sections[SectionMAC], err = s.encoder.EncodeSection(mac); err != nil {
		return nil, fmt.Errorf("failed to encode MAC: %w", err)
	}

	return sections, nil
}

func (s *Serializer) encodeLengthPrefixes(sections map[SectionType]*EncodedSection) (map[SectionType]*EncodedSection, error) {
	lengthSections := make(map[SectionType]*EncodedSection)

	var err error
	for sectionType, section := range sections {
		if lengthSections[sectionType], err = s.encoder.EncodeLengthPrefix(section.Length); err != nil {
			return nil, fmt.Errorf("failed to encode length for %s: %w", sectionType, err)
		}
	}

	return lengthSections, nil
}

func (s *Serializer) buildLengthsHeader(lengthSections map[SectionType]*EncodedSection) []byte {
	lengthsHeader := make([]byte, 0, 16)
	for _, sectionType := range SectionOrder {
		sec, ok := lengthSections[sectionType]
		if !ok || sec == nil {
			panic(fmt.Sprintf("missing encoded length section for %s", sectionType))
		}
		lengthsHeader = append(lengthsHeader, utils.ToBytes[uint32](sec.Length)...)
	}
	return lengthsHeader
}

func (s *Serializer) assembleEncodedHeader(
	lengthsHeader []byte,
	lengthSections map[SectionType]*EncodedSection,
	sections map[SectionType]*EncodedSection,
) []byte {
	var result []byte

	result = append(result, lengthsHeader...)
	for _, sectionType := range SectionOrder {
		sec, ok := lengthSections[sectionType]
		if !ok || sec == nil || sec.Data == nil {
			panic(fmt.Sprintf("missing encoded length prefix for %s", sectionType))
		}
		result = append(result, sec.Data...)
	}

	for _, sectionType := range SectionOrder {
		sec, ok := sections[sectionType]
		if !ok || sec == nil || sec.Data == nil {
			panic(fmt.Sprintf("missing encoded section for %s", sectionType))
		}
		result = append(result, sec.Data...)
	}

	return result
}

func (s *Serializer) serialize(h *Header) []byte {
	data := make([]byte, 0, HeaderDataSize)
	data = append(data, utils.ToBytes[uint16](h.Version)...)
	data = append(data, utils.ToBytes[uint32](h.Flags)...)
	data = append(data, utils.ToBytes[uint64](h.OriginalSize)...)
	return data
}
