package processor

import (
	"fmt"

	"github.com/hambosto/sweetbyte/internal/cipher"
	"github.com/hambosto/sweetbyte/internal/compression"
	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/encoding"
	"github.com/hambosto/sweetbyte/internal/padding"
)

// Processor orchestrates the cryptographic pipeline for in-memory data chunks.
// It applies a series of transformations for both encryption and decryption,
// including compression, padding, dual-layer encryption, and error correction coding.
// This processor is a key component of the streaming layer.
type Processor struct {
	firstCipher  *cipher.AESCipher
	secondCipher *cipher.XChaCha20Cipher
	encoder      *encoding.Encoder
	compressor   *compression.Compressor
	padding      *padding.Padding
}

// NewProcessor creates a new Processor instance.
// It initializes the ciphers, encoder, compressor, and padding components.
// The provided key is split to derive separate keys for the two ciphers.
func NewProcessor(key []byte) (*Processor, error) {
	if len(key) < config.MasterKeySize {
		return nil, fmt.Errorf("encryption key must be at least %d bytes long", config.MasterKeySize)
	}

	firstCipher, err := cipher.NewAESCipher(key[:32])
	if err != nil {
		return nil, fmt.Errorf("failed to create aes cipher: %w", err)
	}

	secondCipher, err := cipher.NewXChaCha20Cipher(key[32:64])
	if err != nil {
		return nil, fmt.Errorf("failed to create chacha20 cipher (key length %d): %w", len(key), err)
	}

	encoder, err := encoding.NewEncoder(config.DataShards, config.ParityShards)
	if err != nil {
		return nil, fmt.Errorf("failed to create encoder: %w", err)
	}

	compressor, err := compression.NewCompressor(compression.LevelBestCompression)
	if err != nil {
		return nil, fmt.Errorf("failed to create compressor: %w", err)
	}

	padder, err := padding.NewPadding(config.PaddingSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create padding: %w", err)
	}

	return &Processor{
		firstCipher:  firstCipher,
		secondCipher: secondCipher,
		encoder:      encoder,
		compressor:   compressor,
		padding:      padder,
	}, nil
}

// Encrypt applies the full encryption pipeline to a byte slice.
// The data is compressed, padded, encrypted with AES, then encrypted again
// with XChaCha20, and finally encoded with Reed-Solomon error correction.
func (p *Processor) Encrypt(data []byte) ([]byte, error) {
	// Step 1: Compress the Padded data
	compressed, err := p.compressor.Compress(data)
	if err != nil {
		return nil, fmt.Errorf("compression failed: %w", err)
	}

	// Step 2: First Pad the data
	padded, err := p.padding.Pad(compressed)
	if err != nil {
		return nil, fmt.Errorf("padding failed: %w", err)
	}

	// Step 3: First encryption with AES
	firstEncrypted, err := p.firstCipher.Encrypt(padded)
	if err != nil {
		return nil, fmt.Errorf("first encryption failed: %w", err)
	}

	// Step 4: Second encryption with ChaCha20
	secondEncrypted, err := p.secondCipher.Encrypt(firstEncrypted)
	if err != nil {
		return nil, fmt.Errorf("second encryption failed: %w", err)
	}

	// Step 5: Encode the encrypted data with Reed-Solomon
	encoded, err := p.encoder.Encode(secondEncrypted)
	if err != nil {
		return nil, fmt.Errorf("encoding failed: %w", err)
	}

	return encoded, nil
}

// Decrypt reverses the encryption pipeline.
// It decodes the data, decrypts it with XChaCha20, then with AES,
// unpads it, and finally decompresses it to restore the original content.
func (p *Processor) Decrypt(data []byte) ([]byte, error) {
	// Step 1: Decode the Reed-Solomon encoded data
	decoded, err := p.encoder.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("decoding failed: %w", err)
	}

	// Step 2: First decryption with ChaCha20 (reverse order)
	firstDecrypted, err := p.secondCipher.Decrypt(decoded)
	if err != nil {
		return nil, fmt.Errorf("first decryption failed: %w", err)
	}

	// Step 3: Second decryption with AES
	secondDecrypted, err := p.firstCipher.Decrypt(firstDecrypted)
	if err != nil {
		return nil, fmt.Errorf("second decryption failed: %w", err)
	}

	// Step 4: Remove padding from decompressed data
	unpadded, err := p.padding.Unpad(secondDecrypted)
	if err != nil {
		return nil, fmt.Errorf("unpadding failed: %w", err)
	}

	// Step 5: Decompress the decrypted data
	decompressed, err := p.compressor.Decompress(unpadded)
	if err != nil {
		return nil, fmt.Errorf("decompression failed: %w", err)
	}

	return decompressed, nil
}
