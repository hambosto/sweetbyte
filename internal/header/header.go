// Package header provides functionality for creating, reading, and writing file headers.
// This includes defining the header structure, handling serialization and deserialization,
// and performing validation and verification to ensure integrity and authenticity.
package header

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
)

// Constants defining the structure and size of the file header.
const (
	// MagicBytes is a 4-byte sequence that identifies the file type.
	// This helps in quickly determining if the file is a SweetByte file.
	MagicBytes        = "SWX4"
	MagicSize         = 4   // MagicSize is the size of the magic bytes.
	VersionSize       = 2   // VersionSize is the size of the version field.
	FlagsSize         = 4   // FlagsSize is the size of the flags field.
	SaltSize          = 32  // SaltSize is the size of the salt used in key derivation.
	OriginalSizeSize  = 8   // OriginalSizeSize is the size of the original file size field.
	IntegrityHashSize = 32  // IntegrityHashSize is the size of the integrity hash.
	AuthTagSize       = 32  // AuthTagSize is the size of the authentication tag.
	ChecksumSize      = 4   // ChecksumSize is the size of the header checksum.
	PaddingSize       = 16  // PaddingSize is the size of the random padding.
	TotalHeaderSize   = 134 // TotalHeaderSize is the total size of the header in bytes.
)

// Version and flag constants for controlling file processing.
const (
	// CurrentVersion is the latest version of the header format.
	// It is used to ensure backward compatibility with older file formats.
	CurrentVersion uint16 = 0x0001
	// FlagCompressed indicates that the file content is compressed.
	FlagCompressed uint32 = 1 << 0
	// FlagEncrypted indicates that the file content is encrypted.
	FlagEncrypted uint32 = 1 << 1
	// FlagIntegrityV2 indicates the use of a specific integrity checking mechanism.
	FlagIntegrityV2 uint32 = 1 << 2
	// FlagAntiTamper indicates that anti-tampering measures are in place.
	FlagAntiTamper uint32 = 1 << 3
	// DefaultFlags represents the standard set of flags applied to new headers.
	// These flags enable all security features by default.
	DefaultFlags = FlagEncrypted | FlagIntegrityV2 | FlagAntiTamper
)

// Header represents the structured data at the beginning of a SweetByte file.
// It contains metadata and security information essential for file processing.
type Header struct {
	magic         [MagicSize]byte         // Magic bytes to identify the file type.
	version       uint16                  // Version of the header format.
	flags         uint32                  // Flags to control file processing options.
	salt          [SaltSize]byte          // Salt for key derivation to protect against rainbow table attacks.
	originalSize  uint64                  // Original size of the file before compression or encryption.
	integrityHash [IntegrityHashSize]byte // Hash of the header's structural data to ensure its integrity.
	authTag       [AuthTagSize]byte       // Authentication tag to verify the header's authenticity.
	checksum      uint32                  // Checksum of the entire header to detect corruption.
	padding       [PaddingSize]byte       // Random padding to make the header size fixed and obscure metadata.
}

// NewHeader creates a new Header with the given parameters.
// It initializes the header with default values, generates random padding,
// and computes all necessary protection fields (integrity hash, auth tag, checksum).
// This ensures that every new header is secure and correctly formatted.
func NewHeader(originalSize uint64, salt []byte, key []byte) (*Header, error) {
	// Validate input parameters to prevent insecure or invalid headers.
	if len(salt) != SaltSize {
		return nil, fmt.Errorf("salt must be exactly %d bytes", SaltSize)
	}
	if len(key) == 0 {
		return nil, fmt.Errorf("key cannot be empty")
	}
	if originalSize == 0 {
		return nil, fmt.Errorf("invalid original size")
	}

	// Initialize the header with provided and default values.
	h := &Header{
		version:      CurrentVersion,
		flags:        DefaultFlags,
		originalSize: originalSize,
	}

	// Set the magic bytes and copy the salt into the header.
	copy(h.magic[:], []byte(MagicBytes))
	copy(h.salt[:], salt)

	// Generate random padding to fill the header to a fixed size.
	// This helps to obscure metadata and prevent certain types of attacks.
	if _, err := rand.Read(h.padding[:]); err != nil {
		return nil, fmt.Errorf("failed to generate padding: %w", err)
	}

	// Compute the integrity hash, authentication tag, and checksum for the header.
	// These are crucial for ensuring the header's security and integrity.
	if err := computeProtection(h, key); err != nil {
		return nil, fmt.Errorf("failed to compute protection: %w", err)
	}

	return h, nil
}

// ReadHeader deserializes a header from an io.Reader.
// It reads the header data from the reader and constructs a Header object.
func ReadHeader(r io.Reader) (*Header, error) {
	h := &Header{}
	// The ReadFrom method handles the actual reading and deserialization.
	if _, err := h.ReadFrom(r); err != nil {
		return nil, err
	}
	return h, nil
}

// WriteTo implements the io.WriterTo interface, serializing the header to an io.Writer.
// This is an efficient way to write the header data to a stream.
func (h *Header) WriteTo(w io.Writer) (int64, error) {
	// Marshal the header into a byte slice.
	data, err := h.MarshalBinary()
	if err != nil {
		return 0, err
	}
	// Write the marshaled data to the writer.
	n, err := w.Write(data)
	return int64(n), err
}

// ReadFrom implements the io.ReaderFrom interface, deserializing the header from an io.Reader.
// It reads the exact size of the header from the reader and then unmarshals the data.
func (h *Header) ReadFrom(r io.Reader) (int64, error) {
	data := make([]byte, TotalHeaderSize)
	// Read the full header data from the reader.
	n, err := io.ReadFull(r, data)
	if err != nil {
		return int64(n), fmt.Errorf("failed to read header data: %w", err)
	}

	// Unmarshal the byte slice into the Header struct.
	if err := h.UnmarshalBinary(data); err != nil {
		return int64(n), err
	}
	return int64(n), nil
}

// MarshalBinary implements the encoding.BinaryMarshaler interface.
// It serializes the Header struct into a byte slice for storage or transmission.
func (h *Header) MarshalBinary() ([]byte, error) {
	// Validate the header fields before serialization to ensure correctness.
	if err := h.validateForSerialization(); err != nil {
		return nil, fmt.Errorf("serialization validation failed: %w", err)
	}

	// Use a buffer to efficiently write the binary data.
	buf := new(bytes.Buffer)
	buf.Grow(TotalHeaderSize)

	// Write each field of the header to the buffer in BigEndian order.
	buf.Write(h.magic[:])
	binary.Write(buf, binary.BigEndian, h.version)
	binary.Write(buf, binary.BigEndian, h.flags)
	buf.Write(h.salt[:])
	binary.Write(buf, binary.BigEndian, h.originalSize)
	buf.Write(h.integrityHash[:])
	buf.Write(h.authTag[:])
	binary.Write(buf, binary.BigEndian, h.checksum)
	buf.Write(h.padding[:])

	return buf.Bytes(), nil
}

// UnmarshalBinary implements the encoding.BinaryUnmarshaler interface.
// It deserializes a byte slice into the Header struct.
func (h *Header) UnmarshalBinary(data []byte) error {
	// Check if the data slice has the expected size.
	if len(data) != TotalHeaderSize {
		return fmt.Errorf("invalid header size")
	}

	// Use a reader to process the byte slice.
	r := bytes.NewReader(data)

	// Read each field from the reader in BigEndian order.
	if _, err := io.ReadFull(r, h.magic[:]); err != nil {
		return err
	}
	if err := binary.Read(r, binary.BigEndian, &h.version); err != nil {
		return err
	}
	if err := binary.Read(r, binary.BigEndian, &h.flags); err != nil {
		return err
	}
	if _, err := io.ReadFull(r, h.salt[:]); err != nil {
		return err
	}
	if err := binary.Read(r, binary.BigEndian, &h.originalSize); err != nil {
		return err
	}
	if _, err := io.ReadFull(r, h.integrityHash[:]); err != nil {
		return err
	}
	if _, err := io.ReadFull(r, h.authTag[:]); err != nil {
		return err
	}
	if err := binary.Read(r, binary.BigEndian, &h.checksum); err != nil {
		return err
	}
	if _, err := io.ReadFull(r, h.padding[:]); err != nil {
		return err
	}

	// Validate the header fields after deserialization to ensure integrity.
	if err := h.validateAfterDeserialization(); err != nil {
		return fmt.Errorf("header validation failed: %w", err)
	}

	return nil
}

// validateForSerialization runs a set of validation checks before serializing the header.
// This ensures that the header is well-formed and all required fields are set.
func (h *Header) validateForSerialization() error {
	validators := []func(*Header) error{
		validateMagicBytes,
		validateVersion,
		validateOriginalSize,
		validateSalt,
		validateIntegrityHash,
		validateAuthTag,
	}

	for _, validator := range validators {
		if err := validator(h); err != nil {
			return err
		}
	}
	return nil
}

// validateAfterDeserialization runs a set of validation checks after deserializing the header.
// This focuses on fields that can be verified without a key.
func (h *Header) validateAfterDeserialization() error {
	validators := []func(*Header) error{
		validateMagicBytes,
		validateVersion,
		validateOriginalSize,
		validateSalt,
	}

	for _, validator := range validators {
		if err := validator(h); err != nil {
			return err
		}
	}
	return nil
}

// validateMagicBytes checks if the header's magic bytes are correct.
func validateMagicBytes(h *Header) error {
	if !hmac.Equal(h.magic[:], []byte(MagicBytes)) {
		return fmt.Errorf("invalid magic bytes")
	}
	return nil
}

// validateVersion checks if the header's version is supported.
func validateVersion(h *Header) error {
	if h.version == 0 {
		return fmt.Errorf("invalid version")
	}
	if h.version > CurrentVersion {
		return fmt.Errorf("unsupported version: %d (maximum supported: %d)", h.version, CurrentVersion)
	}
	return nil
}

// validateOriginalSize checks if the original size is non-zero.
func validateOriginalSize(h *Header) error {
	if h.originalSize == 0 {
		return fmt.Errorf("invalid original size")
	}
	return nil
}

// validateSalt checks if the salt field is not all zeros.
func validateSalt(h *Header) error {
	return validateNonZeroField(h.salt[:], "salt")
}

// validateIntegrityHash checks if the integrity hash field is not all zeros.
func validateIntegrityHash(h *Header) error {
	return validateNonZeroField(h.integrityHash[:], "integrity hash")
}

// validateAuthTag checks if the authentication tag field is not all zeros.
func validateAuthTag(h *Header) error {
	return validateNonZeroField(h.authTag[:], "auth tag")
}

// validateNonZeroField is a helper function to check if a byte slice is all zeros.
func validateNonZeroField(field []byte, fieldName string) error {
	zeroField := make([]byte, len(field))
	if hmac.Equal(field, zeroField) {
		return fmt.Errorf("%s: field cannot be all zeros", fieldName)
	}
	return nil
}

// Magic returns a copy of the magic bytes from the header.
func (h *Header) Magic() []byte {
	cp := make([]byte, len(h.magic))
	copy(cp, h.magic[:])
	return cp
}

// Version returns the version from the header.
func (h *Header) Version() uint16 {
	return h.version
}

// Flags returns the flags from the header.
func (h *Header) Flags() uint32 {
	return h.flags
}

// Salt returns a copy of the salt from the header.
func (h *Header) Salt() []byte {
	cp := make([]byte, len(h.salt))
	copy(cp, h.salt[:])
	return cp
}

// OriginalSize returns the original size of the file from the header.
func (h *Header) OriginalSize() uint64 {
	return h.originalSize
}

// HasFlag checks if a specific flag is set in the header's flags.
func (h *Header) HasFlag(flag uint32) bool {
	return h.flags&flag != 0
}
