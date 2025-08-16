package header

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
)

// Constants defining the structure and size of the file header.
const (
	// MagicBytes is a 4-byte identifier for SweetByte files.
	MagicBytes = "SWX4"
	// MagicSize is the size of the magic bytes.
	MagicSize = 4
	// VersionSize is the size of the version field.
	VersionSize = 2
	// FlagsSize is the size of the flags field.
	FlagsSize = 4
	// SaltSize is the size of the salt used for key derivation.
	SaltSize = 32
	// OriginalSizeSize is the size of the original file size field.
	OriginalSizeSize = 8
	// IntegrityHashSize is the size of the SHA-256 hash of the header.
	IntegrityHashSize = 32
	// AuthTagSize is the size of the HMAC-SHA256 authentication tag.
	AuthTagSize = 32
	// ChecksumSize is the size of the CRC32 checksum.
	ChecksumSize = 4
	// PaddingSize is the size of the random padding.
	PaddingSize = 16
	// TotalHeaderSize is the total size of the header.
	TotalHeaderSize = 134
)

// Constants for header flags, indicating which security features are enabled.
const (
	// CurrentVersion is the latest version of the file format.
	CurrentVersion uint16 = 0x0001
	// FlagCompressed indicates that the data is compressed.
	FlagCompressed uint32 = 1 << 0
	// FlagEncrypted indicates that the data is encrypted.
	FlagEncrypted uint32 = 1 << 1
	// FlagIntegrityV2 indicates that the header has a SHA-256 integrity hash.
	FlagIntegrityV2 uint32 = 1 << 2
	// FlagAntiTamper indicates that the header has an HMAC-SHA256 authentication tag.
	FlagAntiTamper uint32 = 1 << 3

	// DefaultFlags represents the standard set of security features applied to new files.
	DefaultFlags = FlagEncrypted | FlagIntegrityV2 | FlagAntiTamper
)

// Header represents the secure file header.
// It contains all the necessary metadata to decrypt and verify the file,
// including cryptographic salts, integrity checks, and authentication tags.
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

// NewHeader creates a new, fully protected Header.
// It initializes the header with the necessary metadata and then computes
// all the security features (hash, auth tag, checksum).
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

// Read deserializes a header from a reader.
func Read(r io.Reader) (*Header, error) {
	deserializer := NewDeserializer()
	return deserializer.Read(r)
}

// Write serializes the header to a writer.
func (h *Header) Write(w io.Writer) error {
	serializer := NewSerializer()
	return serializer.Write(w, h)
}

// Verify checks the integrity and authenticity of the header.
// It validates the checksum, integrity hash, and authentication tag.
func (h *Header) Verify(key []byte) error {
	verifier := NewVerifier(key)
	return verifier.VerifyAll(h)
}

// Magic returns the magic bytes of the header.
func (h *Header) Magic() []byte {
	result := make([]byte, MagicSize)
	copy(result, h.magic[:])
	return result
}

// Version returns the version of the file format.
func (h *Header) Version() uint16 {
	return h.version
}

// Flags returns the feature flags of the header.
func (h *Header) Flags() uint32 {
	return h.flags
}

// Salt returns the salt used for key derivation.
func (h *Header) Salt() []byte {
	result := make([]byte, SaltSize)
	copy(result, h.salt[:])
	return result
}

// OriginalSize returns the size of the original, unencrypted file.
func (h *Header) OriginalSize() uint64 {
	return h.originalSize
}

// HasFlag checks if a specific flag is set in the header.
func (h *Header) HasFlag(flag uint32) bool {
	return h.flags&flag != 0
}

// secureCompare performs a constant-time comparison of two byte slices.
func secureCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1
}

// uint64ToBytes converts a uint64 to a byte slice.
func uint64ToBytes(v uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, v)
	return buf
}

// uint32ToBytes converts a uint32 to a byte slice.
func uint32ToBytes(v uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, v)
	return buf
}

// uint16ToBytes converts a uint16 to a byte slice.
func uint16ToBytes(v uint16) []byte {
	buf := make([]byte, 2)
	binary.BigEndian.PutUint16(buf, v)
	return buf
}

// bytesToUint64 converts a byte slice to a uint64.
func bytesToUint64(b []byte) uint64 {
	return binary.BigEndian.Uint64(b)
}

// bytesToUint32 converts a byte slice to a uint32.
func bytesToUint32(b []byte) uint32 {
	return binary.BigEndian.Uint32(b)
}

// bytesToUint16 converts a byte slice to a uint16.
func bytesToUint16(b []byte) uint16 {
	return binary.BigEndian.Uint16(b)
}
