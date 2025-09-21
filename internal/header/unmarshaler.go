package header

import (
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/utils"
)

type Unmarshaler struct {
	header     *Header
	serializer *Serializer
	encoder    *SectionEncoder
}

func NewUnmarshaler(header *Header) *Unmarshaler {
	return &Unmarshaler{
		header:     header,
		serializer: NewSerializer(),
		encoder:    NewSectionEncoder(header.encoder),
	}
}

func (u *Unmarshaler) Unmarshal(r io.Reader) error {
	lengthSizes, err := u.readLengthSizes(r)
	if err != nil {
		return fmt.Errorf("failed to read length sizes: %w", err)
	}

	sectionLengths, err := u.readAndDecodeLengths(r, lengthSizes)
	if err != nil {
		return fmt.Errorf("failed to read section lengths: %w", err)
	}

	decodedSections, err := u.readAndDecodeData(r, sectionLengths)
	if err != nil {
		return fmt.Errorf("failed to read and decode data: %w", err)
	}

	u.header.decodedSections = decodedSections

	if !VerifyMagic(u.header.decodedSections[SectionMagic][:MagicSize]) {
		return fmt.Errorf("invalid magic bytes")
	}

	if err := u.serializer.Deserialize(u.header, u.header.decodedSections[SectionHeaderData][:HeaderDataSize]); err != nil {
		return fmt.Errorf("failed to deserialize header: %w", err)
	}

	if err := u.header.Validate(); err != nil {
		return fmt.Errorf("header validation failed: %w", err)
	}

	return nil
}

func (u *Unmarshaler) readLengthSizes(r io.Reader) (map[SectionType]uint32, error) {
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

func (u *Unmarshaler) readAndDecodeLengths(r io.Reader, lengthSizes map[SectionType]uint32) (map[SectionType]uint32, error) {
	sectionLengths := make(map[SectionType]uint32)
	for _, sectionType := range []SectionType{SectionMagic, SectionSalt, SectionHeaderData, SectionMAC} {
		encodedLength := make([]byte, lengthSizes[sectionType])
		if _, err := io.ReadFull(r, encodedLength); err != nil {
			return nil, fmt.Errorf("failed to read encoded length for %s: %w", sectionType, err)
		}
		section := &EncodedSection{Data: encodedLength, Length: lengthSizes[sectionType]}
		length, err := u.encoder.DecodeLengthPrefix(section)
		if err != nil {
			return nil, fmt.Errorf("failed to decode length for %s: %w", sectionType, err)
		}
		sectionLengths[sectionType] = length
	}
	return sectionLengths, nil
}

func (u *Unmarshaler) readAndDecodeData(r io.Reader, sectionLengths map[SectionType]uint32) (map[SectionType][]byte, error) {
	decodedSections := make(map[SectionType][]byte)
	for _, sectionType := range []SectionType{SectionMagic, SectionSalt, SectionHeaderData, SectionMAC} {
		encodedData := make([]byte, sectionLengths[sectionType])
		if _, err := io.ReadFull(r, encodedData); err != nil {
			return nil, fmt.Errorf("failed to read encoded %s: %w", sectionType, err)
		}
		section := &EncodedSection{Data: encodedData, Length: sectionLengths[sectionType]}
		decoded, err := u.encoder.DecodeSection(section)
		if err != nil {
			return nil, fmt.Errorf("failed to decode %s: %w", sectionType, err)
		}
		decodedSections[sectionType] = decoded
	}
	return decodedSections, nil
}
