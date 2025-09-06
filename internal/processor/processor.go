package processor

import (
	"fmt"

	"github.com/hambosto/sweetbyte/internal/cipher"
	"github.com/hambosto/sweetbyte/internal/compression"
	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/encoding"
	"github.com/hambosto/sweetbyte/internal/padding"
)

type Processor interface {
	Encrypt(data []byte) ([]byte, error)
	Decrypt(data []byte) ([]byte, error)
}

type processor struct {
	firstCipher  cipher.AESCipher
	secondCipher cipher.ChaCha20Cipher
	encoder      encoding.Encoder
	compressor   compression.Compressor
	padding      padding.Padding
}

func NewProcessor(key []byte) (Processor, error) {
	if len(key) < config.MasterKeySize {
		return nil, fmt.Errorf("encryption key must be at least %d bytes long, got %d bytes", config.MasterKeySize, len(key))
	}

	firstCipher, err := cipher.NewAESCipher(key[:32])
	if err != nil {
		return nil, fmt.Errorf("failed to initialize AES-256-GCM cipher: %w", err)
	}

	secondCipher, err := cipher.NewChaCha20Cipher(key[32:64])
	if err != nil {
		return nil, fmt.Errorf("failed to initialize XChaCha20-Poly1305 cipher: %w", err)
	}

	encoder, err := encoding.NewEncoder(config.DataShards, config.ParityShards)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Reed-Solomon encoder: %w", err)
	}

	compressor, err := compression.NewCompressor(compression.LevelBestCompression)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize compressor: %w", err)
	}

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

func (p *processor) Encrypt(data []byte) ([]byte, error) {
	compressed, err := p.compressor.Compress(data)
	if err != nil {
		return nil, fmt.Errorf("compression failed: %w", err)
	}

	padded, err := p.padding.Pad(compressed)
	if err != nil {
		return nil, fmt.Errorf("padding failed: %w", err)
	}

	firstEncrypted, err := p.firstCipher.Encrypt(padded)
	if err != nil {
		return nil, fmt.Errorf("first encryption (AES-256-GCM) failed: %w", err)
	}

	secondEncrypted, err := p.secondCipher.Encrypt(firstEncrypted)
	if err != nil {
		return nil, fmt.Errorf("second encryption (XChaCha20-Poly1305) failed: %w", err)
	}

	encoded, err := p.encoder.Encode(secondEncrypted)
	if err != nil {
		return nil, fmt.Errorf("Reed-Solomon encoding failed: %w", err)
	}

	return encoded, nil
}

func (p *processor) Decrypt(data []byte) ([]byte, error) {
	decoded, err := p.encoder.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("Reed-Solomon decoding failed (data may be corrupted): %w", err)
	}

	firstDecrypted, err := p.secondCipher.Decrypt(decoded)
	if err != nil {
		return nil, fmt.Errorf("first decryption (XChaCha20-Poly1305) failed - possible tampering detected: %w", err)
	}

	secondDecrypted, err := p.firstCipher.Decrypt(firstDecrypted)
	if err != nil {
		return nil, fmt.Errorf("second decryption (AES-256-GCM) failed - possible tampering detected: %w", err)
	}

	unpadded, err := p.padding.Unpad(secondDecrypted)
	if err != nil {
		return nil, fmt.Errorf("padding validation failed - possible tampering detected: %w", err)
	}

	decompressed, err := p.compressor.Decompress(unpadded)
	if err != nil {
		return nil, fmt.Errorf("decompression failed - possible data corruption: %w", err)
	}

	return decompressed, nil
}
