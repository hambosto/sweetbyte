// Package header manages the secure header of SweetByte encrypted files.
// It defines the header structure, provides mechanisms for its creation, serialization,
// deserialization, and crucial verification processes to ensure data integrity and authenticity.
package header

import (
	"fmt"
	"io"
)

// Serializer is responsible for converting a Header struct into a byte slice
// suitable for writing to a file. It also performs validation checks before serialization.
type Serializer struct{}

// NewSerializer creates and returns a new Serializer instance.
func NewSerializer() *Serializer {
	return &Serializer{} // Return an empty struct as no state is needed for serialization.
}

// Write serializes the given Header into a byte slice and writes it to the provided io.Writer.
// It first validates the header's integrity before marshalling and writing the data.
func (s *Serializer) Write(w io.Writer, header *Header) error {
	if err := s.Validate(header); err != nil { // Validate the header before attempting to write.
		return fmt.Errorf("serialization validation failed: %w", err) // Return validation error.
	}

	data := s.Marshal(header) // Marshal the header struct into a byte slice.
	n, err := w.Write(data)   // Write the marshaled header data to the writer.
	if err != nil {
		return fmt.Errorf("failed to write header data: %w", err) // Return error if write operation fails.
	}

	if n != len(data) { // Check if the entire header was written successfully.
		return fmt.Errorf("incomplete write: expected %d bytes, wrote %d", len(data), n) // Return error if write is incomplete.
	}

	return nil // Return nil on successful write.
}

// Validate performs a series of checks on the Header to ensure its consistency and validity
// before it is serialized. This helps prevent writing malformed or insecure headers.
func (s *Serializer) Validate(h *Header) error {
	// Verify that the magic bytes match the expected signature.
	if !secureCompare(h.magic[:], []byte(MagicBytes)) {
		return fmt.Errorf("invalid magic bytes") // Return error if magic bytes are incorrect.
	}

	// Ensure the version is not zero (indicating an uninitialized or corrupt header).
	if h.version == 0 {
		return fmt.Errorf("invalid version: %d", h.version) // Return error for invalid version.
	}

	// Ensure the original file size is not zero.
	if h.originalSize == 0 {
		return fmt.Errorf("original size cannot be zero") // Return error if original size is zero.
	}

	// Check that the salt is not all zeros, which would compromise security.
	zeroSalt := make([]byte, SaltSize)
	if secureCompare(h.salt[:], zeroSalt) {
		return fmt.Errorf("salt cannot be all zeros") // Return error for zero salt.
	}

	// Check that the integrity hash is not all zeros.
	zeroHash := make([]byte, IntegrityHashSize)
	if secureCompare(h.integrityHash[:], zeroHash) {
		return fmt.Errorf("integrity hash cannot be all zeros") // Return error for zero integrity hash.
	}

	// Check that the authentication tag is not all zeros.
	zeroAuth := make([]byte, AuthTagSize)
	if secureCompare(h.authTag[:], zeroAuth) {
		return fmt.Errorf("auth tag cannot be all zeros") // Return error for zero authentication tag.
	}

	return nil // Return nil if all validation checks pass.
}

// Marshal converts the Header struct into a flat byte slice according to the defined file format.
// The order of appending fields is crucial for correct serialization and deserialization.
func (s *Serializer) Marshal(h *Header) []byte {
	data := make([]byte, 0, TotalHeaderSize) // Initialize a byte slice with capacity for the total header size.

	data = append(data, h.magic[:]...)                    // Append magic bytes.
	data = append(data, uint16ToBytes(h.version)...)      // Append version (2 bytes).
	data = append(data, uint32ToBytes(h.flags)...)        // Append flags (4 bytes).
	data = append(data, h.salt[:]...)                     // Append salt (32 bytes).
	data = append(data, uint64ToBytes(h.originalSize)...) // Append original size (8 bytes).
	data = append(data, h.integrityHash[:]...)            // Append integrity hash (32 bytes).
	data = append(data, h.authTag[:]...)                  // Append authentication tag (32 bytes).
	data = append(data, uint32ToBytes(h.checksum)...)     // Append checksum (4 bytes).
	data = append(data, h.padding[:]...)                  // Append padding (16 bytes).

	return data // Return the marshaled byte slice.
}
