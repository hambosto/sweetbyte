package header

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
)

// Constants
const (
	MagicBytes        = "SWX4"
	MagicSize         = 4
	VersionSize       = 2
	FlagsSize         = 4
	SaltSize          = 32
	OriginalSizeSize  = 8
	IntegrityHashSize = 32
	AuthTagSize       = 32
	ChecksumSize      = 4
	PaddingSize       = 16
	TotalHeaderSize   = 134
)

const (
	CurrentVersion  uint16 = 0x0001
	FlagCompressed  uint32 = 1 << 0
	FlagEncrypted   uint32 = 1 << 1
	FlagIntegrityV2 uint32 = 1 << 2
	FlagAntiTamper  uint32 = 1 << 3

	// Default flags - strongest security by default
	DefaultFlags = FlagEncrypted | FlagIntegrityV2 | FlagAntiTamper
)

// Header represents the file header with all security features
type Header struct {
	magic         [MagicSize]byte
	version       uint16
	flags         uint32
	salt          [SaltSize]byte
	originalSize  uint64
	integrityHash [IntegrityHashSize]byte
	authTag       [AuthTagSize]byte
	checksum      uint32
	padding       [PaddingSize]byte
}

// NewHeader creates a new header with maximum security
func NewHeader(originalSize uint64, salt []byte, key []byte) (*Header, error) {
	if len(salt) != SaltSize {
		return nil, fmt.Errorf("salt must be exactly %d bytes", SaltSize)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("key cannot be empty")
	}
	if originalSize == 0 {
		return nil, fmt.Errorf("original size cannot be zero")
	}

	h := &Header{
		version:      CurrentVersion,
		flags:        DefaultFlags,
		originalSize: originalSize,
	}

	// Set magic bytes
	copy(h.magic[:], []byte(MagicBytes))

	// Set salt
	copy(h.salt[:], salt)

	// Generate cryptographically secure padding
	if _, err := rand.Read(h.padding[:]); err != nil {
		return nil, fmt.Errorf("failed to generate padding: %w", err)
	}

	// Compute all protection mechanisms
	protector := NewProtector(key)
	if err := protector.ComputeAllProtection(h); err != nil {
		return nil, fmt.Errorf("failed to compute protection: %w", err)
	}

	return h, nil
}

// Read reads and parses a header from the reader
func Read(r io.Reader) (*Header, error) {
	deserializer := NewDeserializer()
	return deserializer.Read(r)
}

// Write writes the header to the writer
func (h *Header) Write(w io.Writer) error {
	serializer := NewSerializer()
	return serializer.Write(w, h)
}

// Verify performs comprehensive verification with maximum security
func (h *Header) Verify(key []byte) error {
	verifier := NewVerifier(key)
	return verifier.VerifyAll(h)
}

// Accessor methods
func (h *Header) Magic() []byte {
	result := make([]byte, MagicSize)
	copy(result, h.magic[:])
	return result
}

func (h *Header) Version() uint16 {
	return h.version
}

func (h *Header) Flags() uint32 {
	return h.flags
}

func (h *Header) Salt() []byte {
	result := make([]byte, SaltSize)
	copy(result, h.salt[:])
	return result
}

func (h *Header) OriginalSize() uint64 {
	return h.originalSize
}

func (h *Header) HasFlag(flag uint32) bool {
	return h.flags&flag != 0
}

// Utility functions
func secureCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

func uint64ToBytes(v uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, v)
	return buf
}

func uint32ToBytes(v uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, v)
	return buf
}

func uint16ToBytes(v uint16) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, v)
	return buf
}

func bytesToUint64(b []byte) uint64 {
	return binary.BigEndian.Uint64(b)
}

func bytesToUint32(b []byte) uint32 {
	return binary.BigEndian.Uint32(b)
}

func bytesToUint16(b []byte) uint16 {
	return binary.BigEndian.Uint16(b)
}
