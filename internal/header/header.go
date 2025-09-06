package header

import (
	"bytes"
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/config"
)

const (
	MagicBytes = "SWX4"
	MagicSize  = 4
	MACSize    = 32
)

const (
	CurrentVersion uint16 = 0x0001
	FlagCompressed uint32 = 1 << 0 // Bit 0
	FlagEncrypted  uint32 = 1 << 1 // Bit 1
	DefaultFlags          = FlagCompressed | FlagEncrypted
)

type Header struct {
	Version      uint16
	Flags        uint32
	OriginalSize uint64
}

func NewHeader(originalSize uint64) (*Header, error) {
	if originalSize == 0 {
		return nil, fmt.Errorf("original size cannot be zero")
	}

	return &Header{
		Version:      CurrentVersion,
		Flags:        DefaultFlags,
		OriginalSize: originalSize,
	}, nil
}

func (h *Header) validate() error {
	if h.Version > CurrentVersion {
		return fmt.Errorf("unsupported version: %d (current: %d)", h.Version, CurrentVersion)
	}

	if h.OriginalSize == 0 {
		return fmt.Errorf("original size cannot be zero")
	}
	return nil
}

func ReadMagic(r io.Reader) ([]byte, error) {
	magic := make([]byte, MagicSize)
	_, err := io.ReadFull(r, magic)
	return magic, err
}

func ReadSalt(r io.Reader) ([]byte, error) {
	salt := make([]byte, config.SaltSize)
	_, err := io.ReadFull(r, salt)
	return salt, err
}

func VerifyMagic(magic []byte) bool {
	return bytes.Equal(magic, []byte(MagicBytes))
}
