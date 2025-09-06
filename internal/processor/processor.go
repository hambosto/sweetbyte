// Package processor provides the core processing logic for encryption and decryption.
package processor

import (
	"fmt"

	"github.com/hambosto/sweetbyte/internal/cipher"
	"github.com/hambosto/sweetbyte/internal/compression"
	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/encoding"
	"github.com/hambosto/sweetbyte/internal/padding"
)

// Processor defines the interface for the core processing logic.
type Processor interface {
	Encrypt(data []byte) ([]byte, error)
	Decrypt(data []byte) ([]byte, error)
}

// processor handles the multi-layered encryption and decryption process.
type processor struct {
	firstCipher  cipher.Cipher
	secondCipher cipher.Cipher
	encoder      encoding.Encoder
	compressor   compression.Compressor
	padding      padding.Padding
}

// NewProcessor creates a new Processor with the given key.
func NewProcessor(key []byte) (Processor, error) {
	// The key must be the correct size.
	if len(key) < config.MasterKeySize {
		return nil, fmt.Errorf("encryption key must be at least %d bytes long, got %d bytes", config.MasterKeySize, len(key))
	}

	// Initialize the first cipher (AES-256-GCM).
	firstCipher, err := cipher.NewAESCipher(key[:32])
	if err != nil {
		return nil, fmt.Errorf("failed to initialize AES-256-GCM cipher: %w", err)
	}

	// Initialize the second cipher (XChaCha20-Poly1305).
	secondCipher, err := cipher.NewXChaCha20Cipher(key[32:64])
	if err != nil {
		return nil, fmt.Errorf("failed to initialize XChaCha20-Poly1305 cipher: %w", err)
	}

	// Initialize the Reed-Solomon encoder.
	encoder, err := encoding.NewEncoder(config.DataShards, config.ParityShards)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Reed-Solomon encoder: %w", err)
	}

	// Initialize the compressor.
	compressor, err := compression.NewCompressor(compression.LevelBestCompression)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize compressor: %w", err)
	}

	// Initialize the padding.
	padder, err := padding.NewPadding(config.PaddingSize)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize PKCS#7 padding: %w", err)
	}

	return &processor{
		firstCipher:  firstCipher,
		secondCipher: secondCipher,
		encoder:      encoder,
		compressor:   compressor,
		padding:      padder,
	}, nil
}

// Encrypt encrypts the given data.
func (p *processor) Encrypt(data []byte) ([]byte, error) {
	// Compress the data.
	compressed, err := p.compressor.Compress(data)
	if err != nil {
		return nil, fmt.Errorf("compression failed: %w", err)
	}

	// Pad the compressed data.
	padded, err := p.padding.Pad(compressed)
	if err != nil {
		return nil, fmt.Errorf("padding failed: %w", err)
	}

	// Encrypt the padded data with the first cipher.
	firstEncrypted, err := p.firstCipher.Encrypt(padded)
	if err != nil {
		return nil, fmt.Errorf("first encryption (AES-256-GCM) failed: %w", err)
	}

	// Encrypt the result with the second cipher.
	secondEncrypted, err := p.secondCipher.Encrypt(firstEncrypted)
	if err != nil {
		return nil, fmt.Errorf("second encryption (XChaCha20-Poly1305) failed: %w", err)
	}

	// Encode the result with Reed-Solomon codes.
	encoded, err := p.encoder.Encode(secondEncrypted)
	if err != nil {
		return nil, fmt.Errorf("Reed-Solomon encoding failed: %w", err)
	}

	return encoded, nil
}

// Decrypt decrypts the given data.
func (p *processor) Decrypt(data []byte) ([]byte, error) {
	// Decode the data with Reed-Solomon codes.
	decoded, err := p.encoder.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("Reed-Solomon decoding failed (data may be corrupted): %w", err)
	}

	// Decrypt the data with the second cipher.
	firstDecrypted, err := p.secondCipher.Decrypt(decoded)
	if err != nil {
		return nil, fmt.Errorf("first decryption (XChaCha20-Poly1305) failed - possible tampering detected: %w", err)
	}

	// Decrypt the result with the first cipher.
	secondDecrypted, err := p.firstCipher.Decrypt(firstDecrypted)
	if err != nil {
		return nil, fmt.Errorf("second decryption (AES-256-GCM) failed - possible tampering detected: %w", err)
	}

	// Unpad the result.
	unpadded, err := p.padding.Unpad(secondDecrypted)
	if err != nil {
		return nil, fmt.Errorf("padding validation failed - possible tampering detected: %w", err)
	}

	// Decompress the result.
	decompressed, err := p.compressor.Decompress(unpadded)
	if err != nil {
		return nil, fmt.Errorf("decompression failed - possible data corruption: %w", err)
	}

	return decompressed, nil
}
