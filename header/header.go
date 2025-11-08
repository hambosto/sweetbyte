package header

import (
	"fmt"
	"io"

	"sweetbyte/config"
)

const (
	MagicBytes     = uint32(0xCAFEBABE)
	MagicSize      = 4
	MACSize        = 32
	HeaderDataSize = 14
	CurrentVersion = 0x0001
	FlagProtected  = 1 << 0
)

type Header struct {
	Version         uint16
	Flags           uint32
	OriginalSize    uint64
	decodedSections map[SectionType][]byte
}

func NewHeader() (*Header, error) {
	return &Header{
		Version:      CurrentVersion,
		OriginalSize: 0,
	}, nil
}

func (h *Header) GetOriginalSize() uint64 {
	return h.OriginalSize
}

func (h *Header) SetOriginalSize(size uint64) {
	h.OriginalSize = size
}

func (h *Header) IsProtected() bool {
	return h.Flags&FlagProtected != 0
}

func (h *Header) SetProtected(protected bool) {
	if protected {
		h.Flags |= FlagProtected
	} else {
		h.Flags &^= FlagProtected
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
	marshaler, err := NewSerializer(h)
	if err != nil {
		return nil, fmt.Errorf("failed to create serializer: %w", err)
	}
	return marshaler.Marshal(salt, key)
}

func (h *Header) Unmarshal(r io.Reader) error {
	unmarshaler, err := NewDeserializer(h)
	if err != nil {
		return fmt.Errorf("failed to create deserializer: %w", err)
	}
	return unmarshaler.Unmarshal(r)
}

func (h *Header) Salt() ([]byte, error) {
	return h.section(SectionSalt, config.SaltSize)
}

func (h *Header) Magic() ([]byte, error) {
	return h.section(SectionMagic, MagicSize)
}

func (h *Header) Verify(key []byte) error {
	if len(key) == 0 {
		return fmt.Errorf("key cannot be empty")
	}

	expectedMAC, err := h.section(SectionMAC, MACSize)
	if err != nil {
		return err
	}
	magic, err := h.section(SectionMagic, MagicSize)
	if err != nil {
		return err
	}
	salt, err := h.section(SectionSalt, config.SaltSize)
	if err != nil {
		return err
	}
	headerData, err := h.section(SectionHeaderData, HeaderDataSize)
	if err != nil {
		return err
	}

	return VerifyMAC(
		key,
		expectedMAC,
		magic,
		salt,
		headerData,
	)
}

func (h *Header) section(st SectionType, minLen int) ([]byte, error) {
	if h.decodedSections == nil {
		return nil, fmt.Errorf("header not unmarshalled yet")
	}

	data, ok := h.decodedSections[st]
	if !ok || data == nil {
		return nil, fmt.Errorf("required section missing or nil")
	}

	if len(data) < minLen {
		return nil, fmt.Errorf("section too short")
	}

	return data[:minLen], nil
}
