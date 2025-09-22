package header

import (
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/encoding"
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

type Header struct {
	Version      uint16
	Flags        uint32
	OriginalSize uint64

	encoder         encoding.Encoder
	decodedSections map[SectionType][]byte
}

func NewHeader() (*Header, error) {
	encoder, err := encoding.NewEncoder(config.DataShards, config.ParityShards)
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

// Getters and Setters
func (h *Header) GetOriginalSize() uint64 {
	return h.OriginalSize
}

func (h *Header) SetOriginalSize(size uint64) {
	h.OriginalSize = size
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

func (h *Header) Validate() error {
	if h.Version > CurrentVersion {
		return fmt.Errorf("unsupported version: %d (current: %d)", h.Version, CurrentVersion)
	}
	if h.OriginalSize == 0 {
		return fmt.Errorf("original size cannot be zero")
	}
	return nil
}

func (h *Header) Marshal(salt, key []byte) ([]byte, error) {
	marshaler := NewSerializer(h)
	return marshaler.Marshal(salt, key)
}

func (h *Header) Unmarshal(r io.Reader) error {
	unmarshaler := NewDeserializer(h)
	return unmarshaler.Unmarshal(r)
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

func (h *Header) VerifyMAC(key []byte) error {
	if h.decodedSections == nil {
		return fmt.Errorf("header not unmarshalled yet")
	}
	if len(key) == 0 {
		return fmt.Errorf("key cannot be empty")
	}
	return VerifyMAC(
		key,
		h.decodedSections[SectionMAC][:MACSize],
		h.decodedSections[SectionMagic][:MagicSize],
		h.decodedSections[SectionSalt][:config.SaltSize],
		h.decodedSections[SectionHeaderData][:HeaderDataSize],
	)
}
