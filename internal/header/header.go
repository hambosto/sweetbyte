package header

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/errors"
)

// Header represents the metadata prepended to encrypted files.
// It provides tamper detection through multiple verification layers:
// - CRC32 checksum for corruption detection
// - SHA-256 integrity hash for structural verification
// - HMAC authentication tag for tampering detection
type Header struct {
	metadata   *Metadata
	protection *Protection
}

// Metadata contains the core header information
type Metadata struct {
	salt         []byte
	originalSize uint64
}

// Protection contains cryptographic verification data
type Protection struct {
	integrityHash []byte
	authTag       []byte
}

// New creates a new header with the specified parameters
func New(salt []byte, size uint64, key []byte) (*Header, error) {
	if err := validateInputs(salt, key); err != nil {
		return nil, err
	}

	metadata := &Metadata{
		salt:         CloneBytes(salt),
		originalSize: size,
	}

	header := &Header{
		metadata:   metadata,
		protection: &Protection{},
	}

	if err := header.computeProtection(key); err != nil {
		return nil, err
	}

	return header, nil
}

// validateInputs checks salt and key parameters
func validateInputs(salt, key []byte) error {
	if len(salt) != config.SaltSizeBytes {
		return fmt.Errorf("%w: expected %d bytes, got %d", errors.ErrInvalidSalt, config.SaltSizeBytes, len(salt))
	}
	if len(key) == 0 {
		return errors.ErrEmptyKey
	}

	return nil
}

// Salt returns a copy of the header's salt
func (h *Header) Salt() []byte {
	return CloneBytes(h.metadata.salt)
}

// OriginalSize returns the stored original plaintext size
func (h *Header) OriginalSize() uint64 {
	return h.metadata.originalSize
}

// Verify authenticates the header using the provided key
func (h *Header) Verify(key []byte) error {
	if len(key) == 0 {
		return errors.ErrEmptyPassword
	}

	verifier := NewVerifier(h, key)
	return verifier.Verify()
}

// WriteTo serializes the header to the writer
func (h *Header) WriteTo(w io.Writer) (int64, error) {
	serializer := NewSerializer(h)
	return serializer.WriteTo(w)
}

// Write is a convenience method that discards the byte count
func (h *Header) Write(w io.Writer) error {
	_, err := h.WriteTo(w)
	return err
}

// ReadFrom deserializes a header from the reader
func ReadFrom(r io.Reader) (*Header, error) {
	deserializer := NewDeserializer()
	return deserializer.ReadHeaderFrom(r)
}

// computeProtection calculates and sets the protection fields
func (h *Header) computeProtection(key []byte) error {
	verifier := NewVerifier(h, key)
	h.protection.integrityHash = verifier.computeIntegrityHash()
	h.protection.authTag = verifier.computeAuthTag()
	return nil
}

// Uint64ToBytes converts a uint64 to big-endian bytes
func Uint64ToBytes(v uint64) []byte {
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, v)
	return buf
}

// Uint32ToBytes converts a uint32 to big-endian bytes
func Uint32ToBytes(v uint32) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, v)
	return buf
}

// CloneBytes creates a deep copy of a byte slice
func CloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	clone := make([]byte, len(b))
	copy(clone, b)
	return clone
}
