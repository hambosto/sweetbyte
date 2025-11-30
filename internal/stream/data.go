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

type DataProcessing struct {
	cipher     *cipher.Cipher
	encoder    *encoding.Encoding
	compressor *compression.Compression
	padder     *padding.Padding
	processing types.Processing
}

func NewDataProcessing(key []byte, processing types.Processing) (*DataProcessing, error) {
	if len(key) < derive.ArgonKeyLen {
		return nil, fmt.Errorf("key must be at least %d bytes, got %d", derive.ArgonKeyLen, len(key))
	}

	cipherInstance, err := cipher.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("cipher initialization: %w", err)
	}

	encoder, err := encoding.NewEncoding(encoding.DataShards, encoding.ParityShards)
	if err != nil {
		return nil, fmt.Errorf("Reed-Solomon encoder initialization: %w", err)
	}

	compressor, err := compression.NewCompression(compression.LevelBestSpeed)
	if err != nil {
		return nil, fmt.Errorf("compressor initialization: %w", err)
	}

	padder, err := padding.NewPadding(padding.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("padding initialization: %w", err)
	}

	return &DataProcessing{
		cipher:     cipherInstance,
		encoder:    encoder,
		compressor: compressor,
		padder:     padder,
		processing: processing,
	}, nil
}

func (p *DataProcessing) Process(ctx context.Context, task types.Task) types.TaskResult {
	if err := ctx.Err(); err != nil {
		return types.TaskResult{Index: task.Index, Err: err}
	}

	var output []byte
	var err error

	switch p.processing {
	case types.Encryption:
		output, err = p.encryptPipeline(task.Data)
	case types.Decryption:
		output, err = p.decryptPipeline(task.Data)
	default:
		err = fmt.Errorf("unknown processing type: %d", p.processing)
	}

	size := len(task.Data)
	if p.processing == types.Decryption && output != nil {
		size = len(output)
	}

	return types.TaskResult{
		Index: task.Index,
		Data:  output,
		Size:  size,
		Err:   err,
	}
}

func (p *DataProcessing) encryptPipeline(data []byte) ([]byte, error) {
	compressed, err := p.compressor.Compress(data)
	if err != nil {
		return nil, fmt.Errorf("compression: %w", err)
	}

	padded, err := p.padder.Pad(compressed)
	if err != nil {
		return nil, fmt.Errorf("padding: %w", err)
	}

	aesEncrypted, err := p.cipher.EncryptAES(padded)
	if err != nil {
		return nil, fmt.Errorf("AES-256-GCM encryption: %w", err)
	}

	chachaEncrypted, err := p.cipher.EncryptChaCha20(aesEncrypted)
	if err != nil {
		return nil, fmt.Errorf("XChaCha20-Poly1305 encryption: %w", err)
	}

	encoded, err := p.encoder.Encode(chachaEncrypted)
	if err != nil {
		return nil, fmt.Errorf("Reed-Solomon encoding: %w", err)
	}

	return encoded, nil
}

func (p *DataProcessing) decryptPipeline(data []byte) ([]byte, error) {
	decoded, err := p.encoder.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("Reed-Solomon decoding (data corrupted): %w", err)
	}

	chachaDecrypted, err := p.cipher.DecryptChaCha20(decoded)
	if err != nil {
		return nil, fmt.Errorf("XChaCha20-Poly1305 decryption (tampering detected): %w", err)
	}

	aesDecrypted, err := p.cipher.DecryptAES(chachaDecrypted)
	if err != nil {
		return nil, fmt.Errorf("AES-256-GCM decryption (tampering detected): %w", err)
	}

	unpadded, err := p.padder.Unpad(aesDecrypted)
	if err != nil {
		return nil, fmt.Errorf("padding validation (tampering detected): %w", err)
	}

	decompressed, err := p.compressor.Decompress(unpadded)
	if err != nil {
		return nil, fmt.Errorf("decompression (data corrupted): %w", err)
	}

	return decompressed, nil
}
