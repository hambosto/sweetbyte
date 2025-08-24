package header

import (
	"fmt"

	"github.com/hambosto/sweetbyte/internal/utils"
)

// FormatVerifier verifies header format compliance
type FormatVerifier struct{}

// NewFormatVerifier creates a new FormatVerifier
func NewFormatVerifier() *FormatVerifier {
	return &FormatVerifier{}
}

// Verify verifies the format of the header
func (fv *FormatVerifier) Verify(h *Header) error {
	if err := fv.verifyMagicBytes(h); err != nil {
		return err
	}
	if err := fv.verifyVersion(h); err != nil {
		return err
	}
	if err := fv.verifyOriginalSize(h); err != nil {
		return err
	}
	if err := fv.verifySecurityFlags(h); err != nil {
		return err
	}
	return nil
}

func (fv *FormatVerifier) verifyMagicBytes(h *Header) error {
	if !utils.SecureCompare(h.magic[:], []byte(MagicBytes)) {
		return fmt.Errorf("invalid magic bytes: expected %s, got %s", MagicBytes, string(h.magic[:]))
	}
	return nil
}

func (fv *FormatVerifier) verifyVersion(h *Header) error {
	if h.version == 0 {
		return fmt.Errorf("invalid version: cannot be zero")
	}
	if h.version > CurrentVersion {
		return fmt.Errorf("unsupported version: %d (maximum supported: %d)", h.version, CurrentVersion)
	}
	return nil
}

func (fv *FormatVerifier) verifyOriginalSize(h *Header) error {
	if h.originalSize == 0 {
		return fmt.Errorf("invalid original size: cannot be zero")
	}
	return nil
}

func (fv *FormatVerifier) verifySecurityFlags(h *Header) error {
	requiredFlags := []struct {
		flag uint32
		name string
	}{
		{FlagEncrypted, "encryption"},
		{FlagIntegrityV2, "integrity v2"},
		{FlagAntiTamper, "anti-tamper"},
	}

	for _, rf := range requiredFlags {
		if !h.HasFlag(rf.flag) {
			return fmt.Errorf("%s flag not set - header created without maximum security", rf.name)
		}
	}

	return nil
}
