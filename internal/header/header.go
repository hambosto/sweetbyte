// Package header provides functionality for creating, reading, and writing file headers.
// This includes defining the header structure, handling serialization and deserialization,
// and performing validation and verification to ensure integrity and authenticity.
package header

import (
	"crypto/rand"
	"fmt"
	"io"
)

// Constants defining the structure and size of the file header.
const (
	MagicBytes        = "SWX4" // MagicBytes is a 4-byte sequence that identifies the file type.
	MagicSize         = 4      // MagicSize is the size of the magic bytes.
	VersionSize       = 2      // VersionSize is the size of the version field.
	FlagsSize         = 4      // FlagsSize is the size of the flags field.
	SaltSize          = 32     // SaltSize is the size of the salt used in key derivation.
	OriginalSizeSize  = 8      // OriginalSizeSize is the size of the original file size field.
	IntegrityHashSize = 32     // IntegrityHashSize is the size of the integrity hash.
	AuthTagSize       = 32     // AuthTagSize is the size of the authentication tag.
	ChecksumSize      = 4      // ChecksumSize is the size of the header checksum.
	PaddingSize       = 16     // PaddingSize is the size of the random padding.
	TotalHeaderSize   = 134    // TotalHeaderSize is the total size of the header in bytes.
)

// Version and flag constants for controlling file processing.
const (
	CurrentVersion  uint16 = 0x0001 // CurrentVersion is the latest version of the header format.
	FlagCompressed  uint32 = 1 << 0 // FlagCompressed indicates that the file content is compressed.
	FlagEncrypted   uint32 = 1 << 1 // FlagEncrypted indicates that the file content is encrypted.
	FlagIntegrityV2 uint32 = 1 << 2 // FlagIntegrityV2 indicates the use of a specific integrity checking mechanism.
	FlagAntiTamper  uint32 = 1 << 3 // FlagAntiTamper indicates that anti-tampering measures are in place.
	// DefaultFlags represents the standard set of flags applied to new headers.
	DefaultFlags = FlagEncrypted | FlagIntegrityV2 | FlagAntiTamper
)

// Header represents the structured data at the beginning of a SweetByte file.
// It contains metadata and security information essential for file processing.
// The fields are private and accessed via getter methods to ensure immutability.
type Header struct {
	magic         [MagicSize]byte         // Magic bytes to identify the file type.
	version       uint16                  // Version of the header format.
	flags         uint32                  // Flags indicating processing options (e.g., compression, encryption).
	salt          [SaltSize]byte          // Salt for key derivation, enhancing security.
	originalSize  uint64                  // Original size of the file before any processing.
	integrityHash [IntegrityHashSize]byte // Hash of the header's structural components to detect corruption.
	authTag       [AuthTagSize]byte       // Authentication tag to verify the header's authenticity.
	checksum      uint32                  // Checksum of the entire header for a quick integrity check.
	padding       [PaddingSize]byte       // Random padding to obscure the header size and prevent certain attacks.
}

// NewHeader creates a new Header with the given parameters.
// It initializes the header with default values, generates random padding,
// and computes all necessary protection fields (integrity hash, auth tag, checksum).
func NewHeader(originalSize uint64, salt []byte, key []byte) (*Header, error) {
	// Validate the input parameters before proceeding.
	if err := validateNewHeaderParams(originalSize, salt, key); err != nil {
		return nil, err
	}

	// Initialize the header with basic information.
	header := &Header{
		version:      CurrentVersion,
		flags:        DefaultFlags,
		originalSize: originalSize,
	}

	// Set the magic bytes and the provided salt.
	copy(header.magic[:], []byte(MagicBytes))
	copy(header.salt[:], salt)

	// Generate random data for the padding field.
	if err := generatePadding(header); err != nil {
		return nil, err
	}

	// Compute and set the integrity hash, authentication tag, and checksum.
	protector := NewProtector(key)
	if err := protector.ComputeAllProtection(header); err != nil {
		return nil, fmt.Errorf("failed to compute protection: %w", err)
	}

	return header, nil
}

// Read deserializes a header from an io.Reader.
// It uses a Deserializer to handle the reading and parsing process.
func Read(r io.Reader) (*Header, error) {
	deserializer := NewDeserializer()
	return deserializer.Read(r)
}

// Write serializes the header to an io.Writer.
// It uses a Serializer to handle the writing process.
func (h *Header) Write(w io.Writer) error {
	serializer := NewSerializer()
	return serializer.Write(w, h)
}

// Verify checks the integrity and authenticity of the header using a provided key.
// It uses a Verifier to perform a comprehensive set of checks.
func (h *Header) Verify(key []byte) error {
	verifier := NewVerifier(key)
	return verifier.VerifyAll(h)
}

// Magic returns a copy of the magic bytes.
func (h *Header) Magic() []byte {
	result := make([]byte, MagicSize)
	copy(result, h.magic[:])
	return result
}

// Version returns the header version.
func (h *Header) Version() uint16 {
	return h.version
}

// Flags returns the header flags.
func (h *Header) Flags() uint32 {
	return h.flags
}

// Salt returns a copy of the salt.
func (h *Header) Salt() []byte {
	result := make([]byte, SaltSize)
	copy(result, h.salt[:])
	return result
}

// OriginalSize returns the original size of the file.
func (h *Header) OriginalSize() uint64 {
	return h.originalSize
}

// HasFlag checks if a specific flag is set in the header.
func (h *Header) HasFlag(flag uint32) bool {
	return h.flags&flag != 0
}

// validateNewHeaderParams ensures that the parameters for creating a new header are valid.
func validateNewHeaderParams(originalSize uint64, salt []byte, key []byte) error {
	if len(salt) != SaltSize {
		return fmt.Errorf("salt must be exactly %d bytes", SaltSize)
	}
	if len(key) == 0 {
		return fmt.Errorf("key cannot be empty")
	}
	if originalSize == 0 {
		return fmt.Errorf("original size cannot be zero")
	}
	return nil
}

// generatePadding fills the header's padding field with random bytes.
func generatePadding(header *Header) error {
	if _, err := rand.Read(header.padding[:]); err != nil {
		return fmt.Errorf("failed to generate padding: %w", err)
	}
	return nil
}
