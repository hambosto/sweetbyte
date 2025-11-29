package stream

import (
	"context"
	"fmt"

	"github.com/hambosto/sweetbyte/internal/cipher"
	"github.com/hambosto/sweetbyte/internal/compression"
	"github.com/hambosto/sweetbyte/internal/derive"
	"github.com/hambosto/sweetbyte/internal/encoding"
	"github.com/hambosto/sweetbyte/internal/padding"
	"github.com/hambosto/sweetbyte/internal/types"
)

type TaskProcessor struct {
	cipher     *cipher.Cipher
	encoder    *encoding.Encoding
	compressor *compression.Compression
	padding    *padding.Padding
	processing types.Processing
}

func NewTaskProcessor(key []byte, processing types.Processing) (*TaskProcessor, error) {
	if len(key) < derive.ArgonKeyLen {
		return nil, fmt.Errorf("encryption key must be at least %d bytes long, got %d bytes", derive.ArgonKeyLen, len(key))
	}

	cipherInstance, err := cipher.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize unified cipher: %w", err)
	}

	encoder, err := encoding.NewEncoding(encoding.DataShards, encoding.ParityShards)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Reed-Solomon encoder: %w", err)
	}

	compressor, err := compression.NewCompression(compression.LevelBestSpeed)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize compressor: %w", err)
	}

	padder, err := padding.NewPadding(padding.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize PKCS#7 padding: %w", err)
	}

	return &TaskProcessor{
		cipher:     cipherInstance,
		encoder:    encoder,
		compressor: compressor,
		padding:    padder,
		processing: processing,
	}, nil
}

func (tp *TaskProcessor) Process(ctx context.Context, task types.Task) types.TaskResult {
	select {
	case <-ctx.Done():

		return types.TaskResult{Index: task.Index, Err: ctx.Err()}
	default:
	}

	var output []byte
	var err error

	switch tp.processing {
	case types.Encryption:
		output, err = tp.encryptionPipeline(task.Data)
	case types.Decryption:
		output, err = tp.decryptionPipeline(task.Data)
	default:
		err = fmt.Errorf("unknown processing type: %d", tp.processing)
	}

	size := len(task.Data)
	if tp.processing == types.Decryption && output != nil {
		size = len(output)
	}

	return types.TaskResult{
		Index: task.Index,
		Data:  output,
		Size:  size,
		Err:   err,
	}
}

func (tp *TaskProcessor) encryptionPipeline(data []byte) ([]byte, error) {
	compressed, err := tp.compressor.Compress(data)
	if err != nil {
		return nil, fmt.Errorf("compression failed: %w", err)
	}

	padded, err := tp.padding.Pad(compressed)
	if err != nil {
		return nil, fmt.Errorf("padding failed: %w", err)
	}

	firstEncrypted, err := tp.cipher.EncryptAES(padded)
	if err != nil {
		return nil, fmt.Errorf("first encryption (AES-256-GCM) failed: %w", err)
	}

	secondEncrypted, err := tp.cipher.EncryptChaCha20(firstEncrypted)
	if err != nil {
		return nil, fmt.Errorf("second encryption (XChaCha20-Poly1305) failed: %w", err)
	}

	encoded, err := tp.encoder.Encode(secondEncrypted)
	if err != nil {
		return nil, fmt.Errorf("Reed-Solomon encoding failed: %w", err)
	}

	return encoded, nil
}

func (tp *TaskProcessor) decryptionPipeline(data []byte) ([]byte, error) {
	decoded, err := tp.encoder.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("Reed-Solomon decoding failed (data may be corrupted): %w", err)
	}

	firstDecrypted, err := tp.cipher.DecryptChaCha20(decoded)
	if err != nil {
		return nil, fmt.Errorf("first decryption (XChaCha20-Poly1305) failed - possible tampering detected: %w", err)
	}

	secondDecrypted, err := tp.cipher.DecryptAES(firstDecrypted)
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
