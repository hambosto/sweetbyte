package stream

import (
	"context"
	"fmt"

	"sweetbyte/cipher"
	"sweetbyte/compression"
	"sweetbyte/config"
	"sweetbyte/derive"
	"sweetbyte/encoding"
	"sweetbyte/padding"
	"sweetbyte/types"
)

type TaskProcessor struct {
	firstCipher  *cipher.AESCipher
	secondCipher *cipher.ChaCha20Cipher
	encoder      *encoding.Encoding
	compressor   *compression.Compression
	padding      *padding.Padding
	processing   types.Processing
}

func NewTaskProcessor(key []byte, processing types.Processing) (*TaskProcessor, error) {
	if len(key) < derive.ArgonKeyLen {
		return nil, fmt.Errorf("encryption key must be at least %d bytes long, got %d bytes", derive.ArgonKeyLen, len(key))
	}

	firstCipher, err := cipher.NewAESCipher(key[:32])
	if err != nil {
		return nil, fmt.Errorf("failed to initialize AES-256-GCM cipher: %w", err)
	}

	secondCipher, err := cipher.NewChaCha20Cipher(key[32:64])
	if err != nil {
		return nil, fmt.Errorf("failed to initialize XChaCha20-Poly1305 cipher: %w", err)
	}

	encoder, err := encoding.NewEncoding(config.DataShards, config.ParityShards)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Reed-Solomon encoder: %w", err)
	}

	compressor, err := compression.NewCompression(compression.LevelBestSpeed)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize compressor: %w", err)
	}

	padder, err := padding.NewPadding(config.PaddingSize)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize PKCS#7 padding: %w", err)
	}

	return &TaskProcessor{
		firstCipher:  firstCipher,
		secondCipher: secondCipher,
		encoder:      encoder,
		compressor:   compressor,
		padding:      padder,
		processing:   processing,
	}, nil
}

func (tp *TaskProcessor) Process(ctx context.Context, task types.Task) types.TaskResult {
	select {
	case <-ctx.Done():
		return types.TaskResult{
			Index: task.Index,
			Err:   ctx.Err(),
		}
	default:
	}

	var output []byte
	var err error

	switch tp.processing {
	case types.Encryption:
		output, err = tp.Encryption(task.Data)
	case types.Decryption:
		output, err = tp.Decryption(task.Data)
	default:
		err = fmt.Errorf("unknown processing type: %d", tp.processing)
	}

	size := len(task.Data)
	if tp.processing == types.Decryption {
		size = len(output)
	}

	return types.TaskResult{
		Index: task.Index,
		Data:  output,
		Size:  size,
		Err:   err,
	}
}

func (tp *TaskProcessor) Encryption(data []byte) ([]byte, error) {
	compressed, err := tp.compressor.Compress(data)
	if err != nil {
		return nil, fmt.Errorf("compression failed: %w", err)
	}

	padded, err := tp.padding.Pad(compressed)
	if err != nil {
		return nil, fmt.Errorf("padding failed: %w", err)
	}

	firstEncrypted, err := tp.firstCipher.Encrypt(padded)
	if err != nil {
		return nil, fmt.Errorf("first encryption (AES-256-GCM) failed: %w", err)
	}

	secondEncrypted, err := tp.secondCipher.Encrypt(firstEncrypted)
	if err != nil {
		return nil, fmt.Errorf("second encryption (XChaCha20-Poly1305) failed: %w", err)
	}

	encoded, err := tp.encoder.Encode(secondEncrypted)
	if err != nil {
		return nil, fmt.Errorf("Reed-Solomon encoding failed: %w", err)
	}

	return encoded, nil
}

func (tp *TaskProcessor) Decryption(data []byte) ([]byte, error) {
	decoded, err := tp.encoder.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("Reed-Solomon decoding failed (data may be corrupted): %w", err)
	}

	firstDecrypted, err := tp.secondCipher.Decrypt(decoded)
	if err != nil {
		return nil, fmt.Errorf("first decryption (XChaCha20-Poly1305) failed - possible tampering detected: %w", err)
	}

	secondDecrypted, err := tp.firstCipher.Decrypt(firstDecrypted)
	if err != nil {
		return nil, fmt.Errorf("second decryption (AES-256-GCM) failed - possible tampering detected: %w", err)
	}

	unpadded, err := tp.padding.Unpad(secondDecrypted)
	if err != nil {
		return nil, fmt.Errorf("padding validation failed - possible tampering detected: %w", err)
	}

	decompressed, err := tp.compressor.Decompress(unpadded)
	if err != nil {
		return nil, fmt.Errorf("decompression failed - possible data corruption: %w", err)
	}

	return decompressed, nil
}
