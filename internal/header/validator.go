package header

import (
	"fmt"

	"github.com/hambosto/sweetbyte/internal/utils"
)

// Validator validates header fields
type Validator struct{}

// NewValidator creates a new Validator
func NewValidator() *Validator {
	return &Validator{}
}

// ValidateForSerialization validates header fields before serialization
func (v *Validator) ValidateForSerialization(h *Header) error {
	validators := []func(*Header) error{
		v.validateMagicBytes,
		v.validateVersion,
		v.validateOriginalSize,
		v.validateSalt,
		v.validateIntegrityHash,
		v.validateAuthTag,
	}

	for _, validator := range validators {
		if err := validator(h); err != nil {
			return err
		}
	}

	return nil
}

// ValidateAfterDeserialization validates header fields after deserialization
func (v *Validator) ValidateAfterDeserialization(h *Header) error {
	validators := []func(*Header) error{
		v.validateMagicBytes,
		v.validateVersion,
		v.validateOriginalSize,
		v.validateSalt,
	}

	for _, validator := range validators {
		if err := validator(h); err != nil {
			return err
		}
	}

	return nil
}

func (v *Validator) validateMagicBytes(h *Header) error {
	if !utils.SecureCompare(h.magic[:], []byte(MagicBytes)) {
		return fmt.Errorf("invalid magic bytes: expected %s, got %s", MagicBytes, string(h.magic[:]))
	}
	return nil
}

func (v *Validator) validateVersion(h *Header) error {
	if h.version == 0 {
		return fmt.Errorf("invalid version: cannot be zero")
	}
	if h.version > CurrentVersion {
		return fmt.Errorf("unsupported version: %d (maximum supported: %d)", h.version, CurrentVersion)
	}
	return nil
}

func (v *Validator) validateOriginalSize(h *Header) error {
	if h.originalSize == 0 {
		return fmt.Errorf("invalid original size: cannot be zero")
	}
	return nil
}

func (v *Validator) validateSalt(h *Header) error {
	return v.validateNonZeroField(h.salt[:], "salt")
}

func (v *Validator) validateIntegrityHash(h *Header) error {
	return v.validateNonZeroField(h.integrityHash[:], "integrity hash")
}

func (v *Validator) validateAuthTag(h *Header) error {
	return v.validateNonZeroField(h.authTag[:], "auth tag")
}

func (v *Validator) validateNonZeroField(field []byte, fieldName string) error {
	zeroField := make([]byte, len(field))
	if utils.SecureCompare(field, zeroField) {
		return fmt.Errorf("%s cannot be all zeros", fieldName)
	}
	return nil
}
