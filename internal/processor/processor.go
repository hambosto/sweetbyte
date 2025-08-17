// Package processor orchestrates the multi-layered cryptographic and data processing pipeline.
// It integrates various components such as ciphers, compression, padding, and error correction
// to perform the core encryption and decryption operations on data chunks.
package processor

import (
	"fmt"

	"github.com/hambosto/sweetbyte/internal/cipher"
	"github.com/hambosto/sweetbyte/internal/compression"
	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/encoding"
	"github.com/hambosto/sweetbyte/internal/padding"
)

// Processor represents the core processing unit that applies a series of transformations
// (compression, padding, encryption, encoding) to data during encryption and their inverse
// during decryption. It holds instances of all cryptographic and data manipulation components.
type Processor struct {
	firstCipher  *cipher.AESCipher       // The first layer of encryption (AES-256-GCM).
	secondCipher *cipher.XChaCha20Cipher // The second layer of encryption (XChaCha20-Poly1305).
	encoder      *encoding.Encoder       // Handles Reed-Solomon error correction encoding/decoding.
	compressor   *compression.Compressor // Handles Zlib compression/decompression.
	padding      *padding.Padding        // Manages PKCS7 padding/unpadding.
}

// NewProcessor creates and initializes a new Processor instance.
// It sets up all the required cryptographic and data transformation components
// based on the provided master key, splitting it for different ciphers.
// Returns an error if any component fails to initialize or if the key size is insufficient.
func NewProcessor(key []byte) (*Processor, error) {
	if len(key) < config.MasterKeySize {
		return nil, fmt.Errorf("encryption key must be at least %d bytes long, got %d bytes", config.MasterKeySize, len(key)) // Validate key length.
	}

	// Initialize the first cipher (AES-256-GCM) using the first part of the master key.
	firstCipher, err := cipher.NewAESCipher(key[:32])
	if err != nil {
		return nil, fmt.Errorf("failed to initialize AES-256-GCM cipher: %w", err) // Propagate initialization errors.
	}

	// Initialize the second cipher (XChaCha20-Poly1305) using the second part of the master key.
	secondCipher, err := cipher.NewXChaCha20Cipher(key[32:64])
	if err != nil {
		return nil, fmt.Errorf("failed to initialize XChaCha20-Poly1305 cipher: %w", err) // Propagate initialization errors.
	}

	// Initialize the Reed-Solomon encoder with configured data and parity shards.
	encoder, err := encoding.NewEncoder(config.DataShards, config.ParityShards)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Reed-Solomon encoder: %w", err) // Propagate initialization errors.
	}

	// Initialize the Zlib compressor with the best compression level.
	compressor, err := compression.NewCompressor(compression.LevelBestCompression)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize compressor: %w", err) // Propagate initialization errors.
	}

	// Initialize the PKCS#7 padder with the predefined padding size.
	padder, err := padding.NewPadding(config.PaddingSize)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize PKCS#7 padding: %w", err) // Propagate initialization errors.
	}

	// Return the fully initialized Processor.
	return &Processor{
		firstCipher:  firstCipher,
		secondCipher: secondCipher,
		encoder:      encoder,
		compressor:   compressor,
		padding:      padder,
	}, nil
}

// Encrypt applies the full encryption pipeline to a given byte slice.
// The pipeline steps are: Compression -> Padding -> AES-GCM Encrypt -> XChaCha20-Poly1305 Encrypt -> Reed-Solomon Encode.
// Returns the encrypted and encoded data, or an error if any step fails.
func (p *Processor) Encrypt(data []byte) ([]byte, error) {
	// Compress the input data.
	compressed, err := p.compressor.Compress(data)
	if err != nil {
		return nil, fmt.Errorf("compression failed: %w", err) // Handle compression failure.
	}

	// Apply PKCS7 padding to the compressed data.
	padded, err := p.padding.Pad(compressed)
	if err != nil {
		return nil, fmt.Errorf("padding failed: %w", err) // Handle padding failure.
	}

	// First layer of encryption: AES-256-GCM.
	firstEncrypted, err := p.firstCipher.Encrypt(padded)
	if err != nil {
		return nil, fmt.Errorf("first encryption (AES-256-GCM) failed: %w", err) // Handle AES encryption failure.
	}

	// Second layer of encryption: XChaCha20-Poly1305.
	secondEncrypted, err := p.secondCipher.Encrypt(firstEncrypted)
	if err != nil {
		return nil, fmt.Errorf("second encryption (XChaCha20-Poly1305) failed: %w", err) // Handle XChaCha20 encryption failure.
	}

	// Apply Reed-Solomon encoding for error correction.
	encoded, err := p.encoder.Encode(secondEncrypted)
	if err != nil {
		return nil, fmt.Errorf("Reed-Solomon encoding failed: %w", err) // Handle encoding failure.
	}

	return encoded, nil // Return the final encrypted and encoded data.
}

// Decrypt applies the full decryption pipeline to a given byte slice.
// The pipeline steps are the reverse of encryption: Reed-Solomon Decode -> XChaCha20-Poly1305 Decrypt -> AES-GCM Decrypt -> Unpadding -> Decompression.
// Returns the original decrypted data, or an error if any step fails (e.g., due to tampering or corruption).
func (p *Processor) Decrypt(data []byte) ([]byte, error) {
	// Decode the Reed-Solomon encoded data.
	decoded, err := p.encoder.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("Reed-Solomon decoding failed (data may be corrupted): %w", err) // Handle decoding failure, indicating possible corruption.
	}

	// First layer of decryption: XChaCha20-Poly1305.
	firstDecrypted, err := p.secondCipher.Decrypt(decoded)
	if err != nil {
		return nil, fmt.Errorf("first decryption (XChaCha20-Poly1305) failed - possible tampering detected: %w", err) // Handle XChaCha20 decryption failure.
	}

	// Second layer of decryption: AES-256-GCM.
	secondDecrypted, err := p.firstCipher.Decrypt(firstDecrypted)
	if err != nil {
		return nil, fmt.Errorf("second decryption (AES-256-GCM) failed - possible tampering detected: %w", err) // Handle AES decryption failure.
	}

	// Remove PKCS7 padding.
	unpadded, err := p.padding.Unpad(secondDecrypted)
	if err != nil {
		return nil, fmt.Errorf("padding validation failed - possible tampering detected: %w", err) // Handle unpadding failure, indicating possible tampering.
	}

	// Decompress the unpadded data.
	decompressed, err := p.compressor.Decompress(unpadded)
	if err != nil {
		return nil, fmt.Errorf("decompression failed - possible data corruption: %w", err) // Handle decompression failure, indicating possible corruption.
	}

	return decompressed, nil // Return the final decrypted and decompressed data.
}
