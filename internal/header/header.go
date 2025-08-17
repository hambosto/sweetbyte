// Package header manages the secure header of SweetByte encrypted files.
// It defines the header structure, provides mechanisms for its creation, serialization,
// deserialization, and crucial verification processes to ensure data integrity and authenticity.
package header

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
)

const (
	// MagicBytes is a fixed string at the beginning of the header to identify SweetByte files.
	MagicBytes = "SWX4"
	// MagicSize defines the size of the magic bytes field.
	MagicSize = 4
	// VersionSize defines the size of the version field.
	VersionSize = 2
	// FlagsSize defines the size of the flags field.
	FlagsSize = 4
	// SaltSize defines the size of the cryptographic salt used in key derivation.
	SaltSize = 32
	// OriginalSizeSize defines the size of the original file size field.
	OriginalSizeSize = 8
	// IntegrityHashSize defines the size of the SHA-256 hash for header integrity.
	IntegrityHashSize = 32
	// AuthTagSize defines the size of the HMAC-SHA256 authentication tag.
	AuthTagSize = 32
	// ChecksumSize defines the size of the CRC32 checksum.
	ChecksumSize = 4
	// PaddingSize defines the size of the random padding used for alignment and obfuscation.
	PaddingSize = 16
	// TotalHeaderSize is the cumulative size of all fields in the header.
	TotalHeaderSize = 134
)

const (
	// CurrentVersion represents the current version of the SweetByte file format.
	CurrentVersion uint16 = 0x0001
	// FlagCompressed indicates if the file content is compressed.
	FlagCompressed uint32 = 1 << 0
	// FlagEncrypted indicates if the file content is encrypted.
	FlagEncrypted uint32 = 1 << 1
	// FlagIntegrityV2 indicates the presence of a SHA-256 integrity hash.
	FlagIntegrityV2 uint32 = 1 << 2
	// FlagAntiTamper indicates the presence of an HMAC-SHA256 authentication tag.
	FlagAntiTamper uint32 = 1 << 3
	// DefaultFlags are the standard flags set for new SweetByte encrypted files, ensuring encryption, integrity, and anti-tamper features.
	DefaultFlags = FlagEncrypted | FlagIntegrityV2 | FlagAntiTamper
)

// Header represents the fixed-size secure header of a SweetByte file.
// It contains metadata and cryptographic parameters essential for decryption and verification.
type Header struct {
	magic         [MagicSize]byte         // Fixed magic bytes "SWX4" for file identification.
	version       uint16                  // Version of the file format.
	flags         uint32                  // Flags indicating various file properties (e.g., encryption, compression).
	salt          [SaltSize]byte          // Cryptographic salt used for key derivation.
	originalSize  uint64                  // The original size of the file before encryption/compression.
	integrityHash [IntegrityHashSize]byte // SHA-256 hash of specific header fields for integrity verification.
	authTag       [AuthTagSize]byte       // HMAC-SHA256 authentication tag for header authenticity.
	checksum      uint32                  // CRC32 checksum for quick detection of accidental corruption.
	padding       [PaddingSize]byte       // Random padding bytes for fixed header size and obfuscation.
}

// NewHeader creates and initializes a new Header instance with provided parameters.
// It sets magic bytes, version, flags, salt, and original size, then computes
// the integrity hash, authentication tag, and checksum using the provided key.
func NewHeader(originalSize uint64, salt []byte, key []byte) (*Header, error) {
	if len(salt) != SaltSize {
		return nil, fmt.Errorf("salt must be exactly %d bytes", SaltSize) // Validate salt size.
	}
	if len(key) == 0 { // Ensure key is not empty.
		return nil, fmt.Errorf("key cannot be empty") // Return error if key is empty.
	}
	if originalSize == 0 { // Ensure original size is not zero.
		return nil, fmt.Errorf("original size cannot be zero") // Return error if original size is zero.
	}

	// Initialize a new Header struct with default and provided values.
	h := &Header{
		version:      CurrentVersion, // Set the current file format version.
		flags:        DefaultFlags,   // Apply default flags (encrypted, integrityV2, anti-tamper).
		originalSize: originalSize,   // Store the original size of the unencrypted file.
	}

	// Copy magic bytes and salt into the header structure.
	copy(h.magic[:], []byte(MagicBytes))
	copy(h.salt[:], salt)

	// Generate random padding bytes to fill the header.
	if _, err := rand.Read(h.padding[:]); err != nil {
		return nil, fmt.Errorf("failed to generate padding: %w", err) // Handle error during padding generation.
	}

	// Create a new Protector to compute and set integrity hash, auth tag, and checksum.
	protector := NewProtector(key)
	if err := protector.ComputeAllProtection(h); err != nil {
		return nil, fmt.Errorf("failed to compute protection: %w", err) // Handle error during protection computation.
	}

	return h, nil // Return the newly created and protected header.
}

// Read reads a Header from the provided io.Reader.
// It delegates the reading process to a Deserializer.
func Read(r io.Reader) (*Header, error) {
	deserializer := NewDeserializer() // Create a new deserializer.
	return deserializer.Read(r)       // Read the header using the deserializer.
}

// Write writes the Header to the provided io.Writer.
// It delegates the writing process to a Serializer.
func (h *Header) Write(w io.Writer) error {
	serializer := NewSerializer() // Create a new serializer.
	return serializer.Write(w, h) // Write the header using the serializer.
}

// Verify verifies the integrity and authenticity of the Header using the provided key.
// It delegates the verification process to a Verifier.
func (h *Header) Verify(key []byte) error {
	verifier := NewVerifier(key) // Create a new verifier.
	return verifier.VerifyAll(h) // Verify the header using the verifier.
}

// Magic returns a copy of the header's magic bytes.
func (h *Header) Magic() []byte {
	result := make([]byte, MagicSize) // Create a new slice to hold the magic bytes.
	copy(result, h.magic[:])          // Copy the internal magic bytes to the new slice.
	return result                     // Return the copy.
}

// Version returns the version of the file format as stored in the header.
func (h *Header) Version() uint16 {
	return h.version
}

// Flags returns the flags indicating various properties of the file.
func (h *Header) Flags() uint32 {
	return h.flags
}

// Salt returns a copy of the header's cryptographic salt.
func (h *Header) Salt() []byte {
	result := make([]byte, SaltSize) // Create a new slice to hold the salt.
	copy(result, h.salt[:])          // Copy the internal salt to the new slice.
	return result                    // Return the copy.
}

// OriginalSize returns the original size of the file before processing.
func (h *Header) OriginalSize() uint64 {
	return h.originalSize
}

// HasFlag checks if a specific flag is set in the header's flags field.
func (h *Header) HasFlag(flag uint32) bool {
	return h.flags&flag != 0 // Perform a bitwise AND operation to check if the flag is present.
}

// secureCompare performs a constant-time comparison of two byte slices.
// This helps prevent timing attacks when comparing sensitive data like hashes or authentication tags.
func secureCompare(a, b []byte) bool {
	return subtle.ConstantTimeCompare(a, b) == 1 // Use crypto/subtle for constant-time comparison.
}

// uint64ToBytes converts a uint64 value to an 8-byte slice in Big Endian byte order.
func uint64ToBytes(v uint64) []byte {
	buf := make([]byte, 8)             // Create an 8-byte buffer.
	binary.BigEndian.PutUint64(buf, v) // Convert uint64 to bytes and put into buffer.
	return buf                         // Return the byte slice.
}

// uint32ToBytes converts a uint32 value to a 4-byte slice in Big Endian byte order.
func uint32ToBytes(v uint32) []byte {
	buf := make([]byte, 4)             // Create a 4-byte buffer.
	binary.BigEndian.PutUint32(buf, v) // Convert uint32 to bytes and put into buffer.
	return buf                         // Return the byte slice.
}

// uint16ToBytes converts a uint16 value to a 2-byte slice in Big Endian byte order.
func uint16ToBytes(v uint16) []byte {
	buf := make([]byte, 2)             // Create a 2-byte buffer.
	binary.BigEndian.PutUint16(buf, v) // Convert uint16 to bytes and put into buffer.
	return buf                         // Return the byte slice.
}

// bytesToUint64 converts an 8-byte slice in Big Endian byte order to a uint64 value.
func bytesToUint64(b []byte) uint64 {
	return binary.BigEndian.Uint64(b) // Convert bytes to uint64.
}

// bytesToUint32 converts a 4-byte slice in Big Endian byte order to a uint32 value.
func bytesToUint32(b []byte) uint32 {
	return binary.BigEndian.Uint32(b) // Convert bytes to uint32.
}

// bytesToUint16 converts a 2-byte slice in Big Endian byte order to a uint16 value.
func bytesToUint16(b []byte) uint16 {
	return binary.BigEndian.Uint16(b) // Convert bytes to uint16.
}
