package processor

import (
	"fmt"

	"github.com/hambosto/sweetbyte/internal/cipher"
	"github.com/hambosto/sweetbyte/internal/compression"
	"github.com/hambosto/sweetbyte/internal/config"
	"github.com/hambosto/sweetbyte/internal/encoding"
	"github.com/hambosto/sweetbyte/internal/padding"
)

// Processor orchestrates the core transformation pipeline for small payloads
// (in-memory) used by the streaming layer. The pipeline performs, in order:
//   - Encryption: Compress -> Pad -> AES-Encrypt -> XChaCha20-Encrypt -> Encode
//   - Decryption: Decode -> XChaCha20-Decrypt -> AES-Decrypt -> Unpad -> Decompress
//
// The dual-cipher approach (AES then XChaCha20) provides defense-in-depth, while
// Reed–Solomon encoding increases resilience to corruption. Padding randomizes
// sizes to reduce information leakage. For large files, this processor is used
// on fixed-size chunks by the `internal/streaming/` package.
// Processor handles encryption/decryption operations with compression, padding, and encoding
type Processor struct {
	firstCipher  *cipher.AESCipher
	secondCipher *cipher.XChaCha20Cipher
	encoder      *encoding.Encoder
	compressor   *compression.Compressor
	padding      *padding.Padding
}

// NewProcessor creates a new processor with the provided master key. The key is
// expected to be at least `config.MasterKeySize` bytes. It is split as follows:
//   - firstCipher  = key[0:32]  (AES)
//   - secondCipher = key[32:64] (XChaCha20)
//
// Callers in the streaming layer must ensure the key length requirement is met
// (see `internal/streaming/stream_config.go`).
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

// Encrypt compresses, pads, encrypts (AES then XChaCha20), and Reed–Solomon
// encodes the input data. It returns a new byte slice on success.
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

// Decrypt decodes (Reed–Solomon), decrypts (XChaCha20 then AES), removes
// padding, and finally decompresses the input data. It returns a new byte slice
// on success.
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
