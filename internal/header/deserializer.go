// Package header provides functionality for handling file headers,
// including serialization and deserialization of metadata.
package header

import (
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/utils"
)

// Deserializer handles the process of reading and parsing the header data from an io.Reader.
// It reconstructs the Header struct from its serialized and encoded form.
type Deserializer struct {
	header  *Header         // The Header struct to populate with deserialized data.
	encoder *SectionEncoder // The encoder used for decoding Reed-Solomon encoded sections.
}

// NewDeserializer creates a new Deserializer for a given Header.
// It initializes the necessary components, including the section encoder.
func NewDeserializer(header *Header) (*Deserializer, error) {
	encoder, err := NewSectionEncoder()
	if err != nil {
		return nil, fmt.Errorf("failed to create section encoder: %w", err)
	}
	return &Deserializer{
		header:  header,
		encoder: encoder,
	}, nil
}

// Unmarshal reads from an io.Reader, decodes the header sections, and populates the Header struct.
// The process involves several steps:
// 1. Read the sizes of the length prefixes for each section.
// 2. Read and decode the length prefixes to determine the size of each data section.
// 3. Read and decode the actual data for each section.
// 4. Populate the Header struct with the decoded data.
// 5. Verify the integrity and validity of the header.
func (d *Deserializer) Unmarshal(r io.Reader) error {
	// Step 1: Read the fixed-size (16 bytes) header that contains the lengths of the encoded length prefixes.
	lengthSizes, err := d.readLengthSizes(r)
	if err != nil {
		return fmt.Errorf("failed to read length sizes: %w", err)
	}

	// Step 2: Read and decode the variable-size length prefixes for each section.
	sectionLengths, err := d.readAndDecodeLengths(r, lengthSizes)
	if err != nil {
		return fmt.Errorf("failed to read section lengths: %w", err)
	}

	// Step 3: Read and decode the actual data for each section using the lengths obtained in the previous step.
	decodedSections, err := d.readAndDecodeData(r, sectionLengths)
	if err != nil {
		return fmt.Errorf("failed to read and decode data: %w", err)
	}

	// Store the decoded sections in the header for later access (e.g., for MAC verification).
	d.header.decodedSections = decodedSections

	// Step 4: Perform validation checks.
	// Verify that the magic bytes are correct to ensure it's a valid file format.
	if !VerifyMagic(d.header.decodedSections[SectionMagic][:MagicSize]) {
		return fmt.Errorf("invalid magic bytes")
	}

	// Deserialize the core header data (version, flags, original size) into the Header struct.
	if err := d.deserialize(d.header, d.header.decodedSections[SectionHeaderData][:HeaderDataSize]); err != nil {
		return fmt.Errorf("failed to deserialize header: %w", err)
	}

	// Validate the deserialized header fields (e.g., version, original size).
	if err := d.header.Validate(); err != nil {
		return fmt.Errorf("header validation failed: %w", err)
	}

	return nil
}

// readLengthSizes reads the 16-byte block that specifies the size of each section's encoded length prefix.
func (d *Deserializer) readLengthSizes(r io.Reader) (map[SectionType]uint32, error) {
	lengthsHeader := make([]byte, 16)
	if _, err := io.ReadFull(r, lengthsHeader); err != nil {
		return nil, fmt.Errorf("failed to read lengths header: %w", err)
	}
	// The 16-byte header is split into four 4-byte parts, each representing the size of a length prefix.
	return map[SectionType]uint32{
		SectionMagic:      utils.FromBytes[uint32](lengthsHeader[0:4]),
		SectionSalt:       utils.FromBytes[uint32](lengthsHeader[4:8]),
		SectionHeaderData: utils.FromBytes[uint32](lengthsHeader[8:12]),
		SectionMAC:        utils.FromBytes[uint32](lengthsHeader[12:16]),
	}, nil
}

// readAndDecodeLengths reads and decodes the length prefix for each section.
// This gives the size of the actual encoded data for each section.
func (d *Deserializer) readAndDecodeLengths(r io.Reader, lengthSizes map[SectionType]uint32) (map[SectionType]uint32, error) {
	sectionLengths := make(map[SectionType]uint32)
	// Iterate through the sections in their defined order.
	for _, sectionType := range []SectionType{SectionMagic, SectionSalt, SectionHeaderData, SectionMAC} {
		// Read the encoded length prefix.
		encodedLength := make([]byte, lengthSizes[sectionType])
		if _, err := io.ReadFull(r, encodedLength); err != nil {
			return nil, fmt.Errorf("failed to read encoded length for %s: %w", sectionType, err)
		}
		// Decode the length prefix to get the actual length.
		section := &EncodedSection{Data: encodedLength, Length: lengthSizes[sectionType]}
		length, err := d.encoder.DecodeLengthPrefix(section)
		if err != nil {
			return nil, fmt.Errorf("failed to decode length for %s: %w", sectionType, err)
		}
		sectionLengths[sectionType] = length
	}
	return sectionLengths, nil
}

// readAndDecodeData reads and decodes the main data for each section.
func (d *Deserializer) readAndDecodeData(r io.Reader, sectionLengths map[SectionType]uint32) (map[SectionType][]byte, error) {
	decodedSections := make(map[SectionType][]byte)
	// Iterate through the sections in their defined order.
	for _, sectionType := range SectionOrder {
		// Read the encoded section data.
		encodedData := make([]byte, sectionLengths[sectionType])
		if _, err := io.ReadFull(r, encodedData); err != nil {
			return nil, fmt.Errorf("failed to read encoded %s: %w", sectionType, err)
		}
		// Decode the section data.
		section := &EncodedSection{Data: encodedData, Length: sectionLengths[sectionType]}
		decoded, err := d.encoder.DecodeSection(section)
		if err != nil {
			return nil, fmt.Errorf("failed to decode %s: %w", sectionType, err)
		}
		decodedSections[sectionType] = decoded
	}
	return decodedSections, nil
}

// deserialize parses the raw header data byte slice and populates the fields of the Header struct.
func (d *Deserializer) deserialize(h *Header, data []byte) error {
	if len(data) != HeaderDataSize {
		return fmt.Errorf("invalid header data size: expected %d bytes, got %d", HeaderDataSize, len(data))
	}
	// Extract version, flags, and original size from the byte slice.
	h.Version = utils.FromBytes[uint16](data[0:2])
	h.Flags = utils.FromBytes[uint32](data[2:6])
	h.OriginalSize = utils.FromBytes[uint64](data[6:14])
	return nil
}
