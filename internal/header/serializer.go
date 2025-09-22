// Package header provides functionality for handling file headers,
// including serialization and deserialization of metadata.
package header

import (
	"fmt"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/utils"
)

// Serializer handles the process of converting a Header struct into a byte slice.
// It manages the encoding of different header sections and assembles them into the final format.
type Serializer struct {
	header  *Header         // The Header struct containing the data to be serialized.
	encoder *SectionEncoder // The encoder used for creating Reed-Solomon encoded sections.
}

// NewSerializer creates a new Serializer for a given Header.
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

// Marshal converts the Header into its final byte slice representation.
// The process involves several steps:
// 1. Serialize the core header data (version, flags, size).
// 2. Compute a MAC over the magic bytes, salt, and serialized header data.
// 3. Reed-Solomon encode each section (magic, salt, header data, MAC).
// 4. Reed-Solomon encode the lengths of the previously encoded sections.
// 5. Assemble all parts into a final byte slice.
func (s *Serializer) Marshal(salt, key []byte) ([]byte, error) {
	// Validate header fields and inputs before proceeding.
	if err := s.validateInputs(salt, key); err != nil {
		return nil, err
	}

	// Prepare the raw data for each section.
	magic := utils.ToBytes(MagicBytes)
	headerData := s.serialize(s.header)

	// Compute the Message Authentication Code (MAC).
	mac, err := ComputeMAC(key, magic, salt, headerData)
	if err != nil {
		return nil, fmt.Errorf("failed to compute MAC: %w", err)
	}

	// Step 3: Encode the main data sections with Reed-Solomon error correction.
	sections, err := s.encodeSections(magic, salt, headerData, mac)
	if err != nil {
		return nil, err
	}

	// Step 4: Encode the lengths of the data sections. This adds another layer of protection for metadata.
	lengthSections, err := s.encodeLengthPrefixes(sections)
	if err != nil {
		return nil, err
	}

	// Create the initial 16-byte header that contains the lengths of the *length sections*.
	lengthsHeader := s.buildLengthsHeader(lengthSections)

	// Step 5: Assemble all the encoded parts in the correct order.
	return s.assembleEncodedHeader(lengthsHeader, lengthSections, sections), nil
}

// validateInputs checks the header and input parameters for validity.
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

// encodeSections applies Reed-Solomon encoding to the primary header sections.
func (m *Serializer) encodeSections(magic, salt, headerData, mac []byte) (map[SectionType]*EncodedSection, error) {
	sections := make(map[SectionType]*EncodedSection)
	var err error

	// Encode each section and store it in the map.
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

// encodeLengthPrefixes takes the lengths of the encoded data sections and encodes those lengths themselves.
func (m *Serializer) encodeLengthPrefixes(sections map[SectionType]*EncodedSection) (map[SectionType]*EncodedSection, error) {
	lengthSections := make(map[SectionType]*EncodedSection)
	var err error

	// For each section, encode its length.
	for sectionType, section := range sections {
		if lengthSections[sectionType], err = m.encoder.EncodeLengthPrefix(section.Length); err != nil {
			return nil, fmt.Errorf("failed to encode length for %s: %w", sectionType, err)
		}
	}

	return lengthSections, nil
}

// buildLengthsHeader creates the 16-byte header that stores the lengths of the encoded length prefixes.
// This is the very first part of the serialized header.
func (m *Serializer) buildLengthsHeader(lengthSections map[SectionType]*EncodedSection) []byte {
	// This header is a fixed 16 bytes (4 sections * 4 bytes/length).
	lengthsHeader := make([]byte, 0, 16)
	lengthsHeader = append(lengthsHeader, utils.ToBytes(lengthSections[SectionMagic].Length)...)
	lengthsHeader = append(lengthsHeader, utils.ToBytes(lengthSections[SectionSalt].Length)...)
	lengthsHeader = append(lengthsHeader, utils.ToBytes(lengthSections[SectionHeaderData].Length)...)
	lengthsHeader = append(lengthsHeader, utils.ToBytes(lengthSections[SectionMAC].Length)...)
	return lengthsHeader
}

// assembleEncodedHeader concatenates all parts of the header into a single byte slice.
// The order is critical for correct deserialization.
func (m *Serializer) assembleEncodedHeader(
	lengthsHeader []byte,
	lengthSections map[SectionType]*EncodedSection,
	sections map[SectionType]*EncodedSection,
) []byte {
	var result []byte
	// 1. The header of lengths (16 bytes).
	result = append(result, lengthsHeader...)
	// 2. The encoded length prefixes for each section.
	result = append(result, lengthSections[SectionMagic].Data...)
	result = append(result, lengthSections[SectionSalt].Data...)
	result = append(result, lengthSections[SectionHeaderData].Data...)
	result = append(result, lengthSections[SectionMAC].Data...)
	// 3. The encoded data for each section.
	result = append(result, sections[SectionMagic].Data...)
	result = append(result, sections[SectionSalt].Data...)
	result = append(result, sections[SectionHeaderData].Data...)
	result = append(result, sections[SectionMAC].Data...)
	return result
}

// serialize converts the fields of the Header struct into a compact byte slice.
func (s *Serializer) serialize(h *Header) []byte {
	// The data is packed in a specific order: Version, Flags, OriginalSize.
	data := make([]byte, 0, HeaderDataSize)
	data = append(data, utils.ToBytes(h.Version)...)
	data = append(data, utils.ToBytes(h.Flags)...)
	data = append(data, utils.ToBytes(h.OriginalSize)...)
	return data
}
