package header

import (
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/utils"
)

type Deserializer struct {
	header  *Header
	encoder *SectionEncoder
}

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

func (d *Deserializer) Unmarshal(r io.Reader) error {
	lengthSizes, err := d.readLengthSizes(r)
	if err != nil {
		return fmt.Errorf("failed to read length sizes: %w", err)
	}

	sectionLengths, err := d.readAndDecodeLengths(r, lengthSizes)
	if err != nil {
		return fmt.Errorf("failed to read section lengths: %w", err)
	}

	decodedSections, err := d.readAndDecodeData(r, sectionLengths)
	if err != nil {
		return fmt.Errorf("failed to read and decode data: %w", err)
	}

	d.header.decodedSections = decodedSections

	if !VerifyMagic(d.header.decodedSections[SectionMagic][:MagicSize]) {
		return fmt.Errorf("invalid magic bytes")
	}

	if err := d.deserialize(d.header, d.header.decodedSections[SectionHeaderData][:HeaderDataSize]); err != nil {
		return fmt.Errorf("failed to deserialize header: %w", err)
	}

	if err := d.header.Validate(); err != nil {
		return fmt.Errorf("header validation failed: %w", err)
	}

	return nil
}

func (d *Deserializer) readLengthSizes(r io.Reader) (map[SectionType]uint32, error) {
	lengthsHeader := make([]byte, 16)
	if _, err := io.ReadFull(r, lengthsHeader); err != nil {
		return nil, fmt.Errorf("failed to read lengths header: %w", err)
	}
	return map[SectionType]uint32{
		SectionMagic:      utils.FromBytes[uint32](lengthsHeader[0:4]),
		SectionSalt:       utils.FromBytes[uint32](lengthsHeader[4:8]),
		SectionHeaderData: utils.FromBytes[uint32](lengthsHeader[8:12]),
		SectionMAC:        utils.FromBytes[uint32](lengthsHeader[12:16]),
	}, nil
}

func (d *Deserializer) readAndDecodeLengths(r io.Reader, lengthSizes map[SectionType]uint32) (map[SectionType]uint32, error) {
	sectionLengths := make(map[SectionType]uint32)
	for _, sectionType := range []SectionType{SectionMagic, SectionSalt, SectionHeaderData, SectionMAC} {
		encodedLength := make([]byte, lengthSizes[sectionType])
		if _, err := io.ReadFull(r, encodedLength); err != nil {
			return nil, fmt.Errorf("failed to read encoded length for %s: %w", sectionType, err)
		}
		section := &EncodedSection{Data: encodedLength, Length: lengthSizes[sectionType]}
		length, err := d.encoder.DecodeLengthPrefix(section)
		if err != nil {
			return nil, fmt.Errorf("failed to decode length for %s: %w", sectionType, err)
		}
		sectionLengths[sectionType] = length
	}
	return sectionLengths, nil
}

func (d *Deserializer) readAndDecodeData(r io.Reader, sectionLengths map[SectionType]uint32) (map[SectionType][]byte, error) {
	decodedSections := make(map[SectionType][]byte)
	for _, sectionType := range []SectionType{SectionMagic, SectionSalt, SectionHeaderData, SectionMAC} {
		encodedData := make([]byte, sectionLengths[sectionType])
		if _, err := io.ReadFull(r, encodedData); err != nil {
			return nil, fmt.Errorf("failed to read encoded %s: %w", sectionType, err)
		}
		section := &EncodedSection{Data: encodedData, Length: sectionLengths[sectionType]}
		decoded, err := d.encoder.DecodeSection(section)
		if err != nil {
			return nil, fmt.Errorf("failed to decode %s: %w", sectionType, err)
		}
		decodedSections[sectionType] = decoded
	}
	return decodedSections, nil
}

func (d *Deserializer) deserialize(h *Header, data []byte) error {
	if len(data) != HeaderDataSize {
		return fmt.Errorf("invalid header data size: expected %d bytes, got %d", HeaderDataSize, len(data))
	}
	h.Version = utils.FromBytes[uint16](data[0:2])
	h.Flags = utils.FromBytes[uint32](data[2:6])
	h.OriginalSize = utils.FromBytes[uint64](data[6:14])
	return nil
}
