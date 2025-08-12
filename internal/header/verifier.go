package header

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"io"

	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/errors"
)

// Verifier handles header authentication and integrity verification
type Verifier struct {
	header *Header
	key    []byte
}

// NewVerifier creates a new header verifier
func NewVerifier(header *Header, key []byte) *Verifier {
	return &Verifier{
		header: header,
		key:    key,
	}
}

// Verify performs all verification checks
func (v *Verifier) Verify() error {
	if err := v.verifyAuthentication(); err != nil {
		return err
	}
	return v.verifyIntegrity()
}

// verifyAuthentication checks the HMAC authentication tag
func (v *Verifier) verifyAuthentication() error {
	expected := v.computeAuthTag()
	if !hmac.Equal(v.header.protection.authTag, expected) {
		return errors.ErrAuthFailure
	}
	return nil
}

// verifyIntegrity checks the SHA-256 integrity hash
func (v *Verifier) verifyIntegrity() error {
	expected := v.computeIntegrityHash()
	if !bytes.Equal(v.header.protection.integrityHash, expected) {
		return errors.ErrIntegrityFailure
	}
	return nil
}

// computeAuthTag calculates the HMAC authentication tag
func (v *Verifier) computeAuthTag() []byte {
	mac := hmac.New(sha256.New, v.key)
	v.writeCommonFields(mac)
	mac.Write(v.header.protection.integrityHash)
	return mac.Sum(nil)
}

// computeIntegrityHash calculates the SHA-256 integrity hash
func (v *Verifier) computeIntegrityHash() []byte {
	hash := sha256.New()
	v.writeCommonFields(hash)
	return hash.Sum(nil)
}

// writeCommonFields writes the common header fields to a hash
func (v *Verifier) writeCommonFields(w io.Writer) {
	_, _ = w.Write([]byte(config.MagicBytes))
	_, _ = w.Write(v.header.metadata.salt)
	_, _ = w.Write(Uint64ToBytes(v.header.metadata.originalSize))
	_, _ = w.Write(v.header.metadata.nonce)
}
