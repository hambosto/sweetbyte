package header

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/encoding"
	"github.com/hambosto/sweetbyte/internal/utils"
)

const (
	MagicBytes     = "SWX4"
	MagicSize      = 4
	MACSize        = 32
	HeaderDataSize = 14
	CurrentVersion = 0x0001
	FlagCompressed = 1 << 0
	FlagEncrypted  = 1 << 1
	DefaultFlags   = FlagCompressed | FlagEncrypted
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

type Header struct {
	Version      uint16
	Flags        uint32
	OriginalSize uint64

	encoder         encoding.Encoder
	decodedSections map[SectionType][]byte
}

func NewHeader() (*Header, error) {
	encoder, err := encoding.NewEncoder(4, 10)
	if err != nil {
		return nil, fmt.Errorf("failed to create reed-solomon encoder: %w", err)
	}
	return &Header{
		Version:      CurrentVersion,
		Flags:        DefaultFlags,
		OriginalSize: 0,
		encoder:      encoder,
	}, nil
}

func (h *Header) GetOriginalSize() uint64 {
	return h.OriginalSize
}

func (h *Header) SetOriginalSize(size uint64) {
	h.OriginalSize = size
}

func (h *Header) Validate() error {
	if h.Version > CurrentVersion {
		return fmt.Errorf("unsupported version: %d (current: %d)", h.Version, CurrentVersion)
	}
	if h.OriginalSize == 0 {
		return fmt.Errorf("original size cannot be zero")
	}
	return nil
}

func (h *Header) IsCompressed() bool {
	return h.Flags&FlagCompressed != 0
}

func (h *Header) IsEncrypted() bool {
	return h.Flags&FlagEncrypted != 0
}

func (h *Header) SetCompressed(compressed bool) {
	if compressed {
		h.Flags |= FlagCompressed
	} else {
		h.Flags &^= FlagCompressed
	}
}

func (h *Header) SetEncrypted(encrypted bool) {
	if encrypted {
		h.Flags |= FlagEncrypted
	} else {
		h.Flags &^= FlagEncrypted
	}
}

func (h *Header) Serialize() []byte {
	data := make([]byte, 0, HeaderDataSize)
	data = append(data, utils.ToBytes(h.Version)...)
	data = append(data, utils.ToBytes(h.Flags)...)
	data = append(data, utils.ToBytes(h.OriginalSize)...)
	return data
}

func (h *Header) Deserialize(data []byte) error {
	if len(data) != HeaderDataSize {
		return fmt.Errorf("invalid header data size: expected %d bytes, got %d", HeaderDataSize, len(data))
	}
	h.Version = utils.FromBytes[uint16](data[0:2])
	h.Flags = utils.FromBytes[uint32](data[2:6])
	h.OriginalSize = utils.FromBytes[uint64](data[6:14])
	return nil
}

func (h *Header) Marshal(salt, key []byte) ([]byte, error) {
	if err := h.validateInputs(salt, key); err != nil {
		return nil, err
	}
	magic := []byte(MagicBytes)
	headerData := h.Serialize()
	mac, err := computeMAC(key, magic, salt, headerData)
	if err != nil {
		return nil, fmt.Errorf("failed to compute MAC: %w", err)
	}
	sections := make(map[SectionType]*EncodedSection)
	if sections[SectionMagic], err = h.EncodeSection(magic); err != nil {
		return nil, fmt.Errorf("failed to encode magic: %w", err)
	}
	if sections[SectionSalt], err = h.EncodeSection(salt); err != nil {
		return nil, fmt.Errorf("failed to encode salt: %w", err)
	}
	if sections[SectionHeaderData], err = h.EncodeSection(headerData); err != nil {
		return nil, fmt.Errorf("failed to encode header data: %w", err)
	}
	if sections[SectionMAC], err = h.EncodeSection(mac); err != nil {
		return nil, fmt.Errorf("failed to encode MAC: %w", err)
	}
	lengthSections := make(map[SectionType]*EncodedSection)
	for sectionType, section := range sections {
		if lengthSections[sectionType], err = h.EncodeLengthPrefix(section.Length); err != nil {
			return nil, fmt.Errorf("failed to encode length for %s: %w", sectionType, err)
		}
	}
	lengthsHeader := make([]byte, 0, 16)
	lengthsHeader = append(lengthsHeader, utils.ToBytes(lengthSections[SectionMagic].Length)...)
	lengthsHeader = append(lengthsHeader, utils.ToBytes(lengthSections[SectionSalt].Length)...)
	lengthsHeader = append(lengthsHeader, utils.ToBytes(lengthSections[SectionHeaderData].Length)...)
	lengthsHeader = append(lengthsHeader, utils.ToBytes(lengthSections[SectionMAC].Length)...)
	return h.assembleEncodedHeader(lengthsHeader, lengthSections, sections), nil
}

func (h *Header) validateInputs(salt, key []byte) error {
	if err := h.Validate(); err != nil {
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

func (h *Header) assembleEncodedHeader(lengthsHeader []byte, lengthSections map[SectionType]*EncodedSection, sections map[SectionType]*EncodedSection) []byte {
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

func (h *Header) Unmarshal(r io.Reader) error {
	lengthSizes, err := h.readLengthSizes(r)
	if err != nil {
		return fmt.Errorf("failed to read length sizes: %w", err)
	}
	sectionLengths, err := h.readAndDecodeLengths(r, lengthSizes)
	if err != nil {
		return fmt.Errorf("failed to read section lengths: %w", err)
	}
	decodedSections, err := h.readAndDecodeData(r, sectionLengths)
	if err != nil {
		return fmt.Errorf("failed to read and decode data: %w", err)
	}
	h.decodedSections = decodedSections
	if !VerifyMagic(h.decodedSections[SectionMagic][:MagicSize]) {
		return fmt.Errorf("invalid magic bytes")
	}
	if err := h.Deserialize(h.decodedSections[SectionHeaderData][:HeaderDataSize]); err != nil {
		return fmt.Errorf("failed to deserialize header: %w", err)
	}
	if err := h.Validate(); err != nil {
		return fmt.Errorf("header validation failed: %w", err)
	}
	return nil
}

func (h *Header) readLengthSizes(r io.Reader) (map[SectionType]uint32, error) {
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

func (h *Header) readAndDecodeLengths(r io.Reader, lengthSizes map[SectionType]uint32) (map[SectionType]uint32, error) {
	sectionLengths := make(map[SectionType]uint32)
	for _, sectionType := range []SectionType{SectionMagic, SectionSalt, SectionHeaderData, SectionMAC} {
		encodedLength := make([]byte, lengthSizes[sectionType])
		if _, err := io.ReadFull(r, encodedLength); err != nil {
			return nil, fmt.Errorf("failed to read encoded length for %s: %w", sectionType, err)
		}
		section := &EncodedSection{Data: encodedLength, Length: lengthSizes[sectionType]}
		length, err := h.DecodeLengthPrefix(section)
		if err != nil {
			return nil, fmt.Errorf("failed to decode length for %s: %w", sectionType, err)
		}
		sectionLengths[sectionType] = length
	}
	return sectionLengths, nil
}

func (h *Header) readAndDecodeData(r io.Reader, sectionLengths map[SectionType]uint32) (map[SectionType][]byte, error) {
	decodedSections := make(map[SectionType][]byte)
	for _, sectionType := range []SectionType{SectionMagic, SectionSalt, SectionHeaderData, SectionMAC} {
		encodedData := make([]byte, sectionLengths[sectionType])
		if _, err := io.ReadFull(r, encodedData); err != nil {
			return nil, fmt.Errorf("failed to read encoded %s: %w", sectionType, err)
		}
		section := &EncodedSection{Data: encodedData, Length: sectionLengths[sectionType]}
		decoded, err := h.DecodeSection(section)
		if err != nil {
			return nil, fmt.Errorf("failed to decode %s: %w", sectionType, err)
		}
		decodedSections[sectionType] = decoded
	}
	return decodedSections, nil
}

func (h *Header) Salt() ([]byte, error) {
	if h.decodedSections == nil {
		return nil, fmt.Errorf("header not unmarshalled yet")
	}
	return h.decodedSections[SectionSalt][:config.SaltSize], nil
}

func (h *Header) Magic() ([]byte, error) {
	if h.decodedSections == nil {
		return nil, fmt.Errorf("header not unmarshalled yet")
	}
	return h.decodedSections[SectionMagic][:MagicSize], nil
}

func VerifyMagic(magic []byte) bool {
	return bytes.Equal(magic, []byte(MagicBytes))
}

func (h *Header) VerifyMAC(key []byte) error {
	if h.decodedSections == nil {
		return fmt.Errorf("header not unmarshalled yet")
	}
	if len(key) == 0 {
		return fmt.Errorf("key cannot be empty")
	}
	return verifyMAC(
		key,
		h.decodedSections[SectionMAC][:MACSize],
		h.decodedSections[SectionMagic][:MagicSize],
		h.decodedSections[SectionSalt][:config.SaltSize],
		h.decodedSections[SectionHeaderData][:HeaderDataSize],
	)
}

func computeMAC(key []byte, parts ...[]byte) ([]byte, error) {
	if len(key) == 0 {
		return nil, fmt.Errorf("key cannot be empty")
	}
	mac := hmac.New(sha256.New, key)
	for i, part := range parts {
		if len(part) == 0 {
			continue
		}
		if _, err := mac.Write(part); err != nil {
			return nil, fmt.Errorf("failed to write part %d to HMAC: %w", i, err)
		}
	}
	return mac.Sum(nil), nil
}

func verifyMAC(key, expectedMAC []byte, parts ...[]byte) error {
	computedMAC, err := computeMAC(key, parts...)
	if err != nil {
		return fmt.Errorf("failed to compute MAC: %w", err)
	}
	if !hmac.Equal(expectedMAC, computedMAC) {
		return fmt.Errorf("MAC verification failed")
	}
	return nil
}

// EncodeSection encodes a data section with Reed-Solomon.
func (h *Header) EncodeSection(data []byte) (*EncodedSection, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("data cannot be empty")
	}

	encoded, err := h.encoder.Encode(data)
	if err != nil {
		return nil, fmt.Errorf("failed to encode data: %w", err)
	}

	return &EncodedSection{
		Data:   encoded,
		Length: uint32(len(encoded)),
	}, nil
}

// DecodeSection decodes a Reed-Solomon encoded section.
func (h *Header) DecodeSection(section *EncodedSection) ([]byte, error) {
	if section == nil || len(section.Data) == 0 {
		return nil, fmt.Errorf("invalid encoded section")
	}

	decoded, err := h.encoder.Decode(section.Data)
	if err != nil {
		return nil, fmt.Errorf("failed to decode data: %w", err)
	}

	return decoded, nil
}

// EncodeLengthPrefix encodes a length value for section metadata.
func (h *Header) EncodeLengthPrefix(length uint32) (*EncodedSection, error) {
	lengthBytes := utils.ToBytes(length)
	return h.EncodeSection(lengthBytes)
}

// DecodeLengthPrefix decodes a length value from section metadata.
func (h *Header) DecodeLengthPrefix(section *EncodedSection) (uint32, error) {
	decoded, err := h.DecodeSection(section)
	if err != nil {
		return 0, err
	}

	if len(decoded) < 4 {
		return 0, fmt.Errorf("invalid length prefix size")
	}

	return utils.FromBytes[uint32](decoded[:4]), nil
}
