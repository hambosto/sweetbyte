package flow

import (
	"fmt"

	"github.com/hambosto/sweetbyte/internal/cipher"
	"github.com/hambosto/sweetbyte/internal/compression"
	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/encoding"
	"github.com/hambosto/sweetbyte/internal/padding"
	"github.com/hambosto/sweetbyte/internal/types"
)

// Processor handles encryption/decryption operations with compression, padding, and encoding
type Processor struct {
	firstCipher  *cipher.AESCipher
	secondCipher *cipher.XChaCha20Cipher
	encoder      *encoding.Encoder
	compressor   *compression.Compressor
	padder       *padding.Padder
}

// NewProcessor creates a new processor with the provided encryption key
func NewProcessor(key []byte) (*Processor, error) {
	if len(key) < config.KeySize {
		return nil, fmt.Errorf("encryption key must be at least %d bytes long", config.KeySize)
	}

	firstCipher, err := cipher.NewAESCipher(key[:config.KeySize])
	if err != nil {
		return nil, fmt.Errorf("failed to create aes cipher: %w", err)
	}

	secondCipher, err := cipher.NewXChaCha20Cipher(key[:config.KeySize])
	if err != nil {
		return nil, fmt.Errorf("failed to create chacha20 cipher: %w", err)
	}

	encoder, err := encoding.NewEncoder(config.DataShards, config.ParityShards)
	if err != nil {
		return nil, fmt.Errorf("failed to create encoder: %w", err)
	}

	compressor, err := compression.NewCompressor(types.LevelBestSpeed)
	if err != nil {
		return nil, fmt.Errorf("failed to create compressor: %w", err)
	}

	padder, err := padding.NewPadder(config.PaddingSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create padder: %w", err)
	}

	return &Processor{
		firstCipher:  firstCipher,
		secondCipher: secondCipher,
		encoder:      encoder,
		compressor:   compressor,
		padder:       padder,
	}, nil
}

// Encrypt compresses, pads, encrypts, and encodes the input data
func (p *Processor) Encrypt(data []byte) ([]byte, error) {
	// Step 1: First Pad the data
	padded, err := p.padder.Pad(data)
	if err != nil {
		return nil, fmt.Errorf("padding failed: %w", err)
	}

	// Step 2: Compress the Padded data
	compressed, err := p.compressor.Compress(padded)
	if err != nil {
		return nil, fmt.Errorf("compression failed: %w", err)
	}

	// Step 3: First encryption with AES
	firstEncrypted, err := p.firstCipher.Encrypt(compressed)
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

// Decrypt decodes, decrypts, unpads, and decompresses the input data
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

	// Step 4: Decompress the decrypted data
	decompressed, err := p.compressor.Decompress(secondDecrypted)
	if err != nil {
		return nil, fmt.Errorf("decompression failed: %w", err)
	}

	// Step 5: Remove padding from decompressed data
	unpadded, err := p.padder.Unpad(decompressed)
	if err != nil {
		return nil, fmt.Errorf("unpadding failed: %w", err)
	}

	return unpadded, nil
}
