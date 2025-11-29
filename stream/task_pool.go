package stream

import (
	"context"
	"fmt"

	"github.com/hambosto/sweetbyte/cipher"
	"github.com/hambosto/sweetbyte/compression"
	"github.com/hambosto/sweetbyte/derive"
	"github.com/hambosto/sweetbyte/encoding"
	"github.com/hambosto/sweetbyte/padding"
	"github.com/hambosto/sweetbyte/types"
)

// TaskProcessor handles the encryption/decryption processing of individual data chunks.
// It implements a multi-layer security approach with dual encryption, compression,
// and Reed-Solomon encoding for error correction.
type TaskProcessor struct {
	firstCipher  *cipher.AESCipher        // First encryption layer using AES-256-GCM
	secondCipher *cipher.ChaCha20Cipher   // Second encryption layer using XChaCha20-Poly1305
	encoder      *encoding.Encoding       // Reed-Solomon encoder for error correction
	compressor   *compression.Compression // Data compression component
	padding      *padding.Padding         // PKCS#7 padding for block cipher compatibility
	processing   types.Processing         // The type of processing (encryption/decryption)
}

// NewTaskProcessor creates and returns a new TaskProcessor instance with the specified
// key and processing type. It initializes all required cryptographic and processing components.
func NewTaskProcessor(key []byte, processing types.Processing) (*TaskProcessor, error) {
	// Validate key length to ensure it meets minimum requirements
	if len(key) < derive.ArgonKeyLen {
		return nil, fmt.Errorf("encryption key must be at least %d bytes long, got %d bytes", derive.ArgonKeyLen, len(key))
	}

	// Initialize the first cipher with the first 32 bytes of the key (AES-256-GCM)
	firstCipher, err := cipher.NewAESCipher(key[:32])
	if err != nil {
		return nil, fmt.Errorf("failed to initialize AES-256-GCM cipher: %w", err)
	}

	// Initialize the second cipher with the next 32 bytes of the key (XChaCha20-Poly1305)
	secondCipher, err := cipher.NewChaCha20Cipher(key[32:64])
	if err != nil {
		return nil, fmt.Errorf("failed to initialize XChaCha20-Poly1305 cipher: %w", err)
	}

	// Initialize the Reed-Solomon encoder with default data and parity shards
	encoder, err := encoding.NewEncoding(encoding.DataShards, encoding.ParityShards)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Reed-Solomon encoder: %w", err)
	}

	// Initialize the compression component with best speed level
	compressor, err := compression.NewCompression(compression.LevelBestSpeed)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize compressor: %w", err)
	}

	// Initialize the PKCS#7 padding component
	padder, err := padding.NewPadding(padding.BlockSize)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize PKCS#7 padding: %w", err)
	}

	// Create and return the TaskProcessor with all initialized components
	return &TaskProcessor{
		firstCipher:  firstCipher,  // Set the first cipher
		secondCipher: secondCipher, // Set the second cipher
		encoder:      encoder,      // Set the encoder
		compressor:   compressor,   // Set the compressor
		padding:      padder,       // Set the padding component
		processing:   processing,   // Set the processing type
	}, nil
}

// Process executes the appropriate processing pipeline (encryption or decryption)
// on the given task data and returns the result.
func (tp *TaskProcessor) Process(ctx context.Context, task types.Task) types.TaskResult {
	// Check if the context has been cancelled
	select {
	case <-ctx.Done():
		// Return error result with the context error
		return types.TaskResult{Index: task.Index, Err: ctx.Err()}
	default:
	}

	var output []byte // Processed output data
	var err error     // Error from processing

	// Execute the appropriate pipeline based on processing type
	switch tp.processing {
	case types.Encryption:
		// Run encryption pipeline on the task data
		output, err = tp.encryptionPipeline(task.Data)
	case types.Decryption:
		// Run decryption pipeline on the task data
		output, err = tp.decryptionPipeline(task.Data)
	default:
		// Return error for unknown processing type
		err = fmt.Errorf("unknown processing type: %d", tp.processing)
	}

	// Determine the size for progress tracking
	size := len(task.Data) // Default to input size
	if tp.processing == types.Decryption && output != nil {
		// For decryption, use output size as decompressed data size
		size = len(output)
	}

	// Return the task result with processed data
	return types.TaskResult{
		Index: task.Index, // Preserve the original task index
		Data:  output,     // Set the processed output data
		Size:  size,       // Set the size for progress tracking
		Err:   err,        // Set any error that occurred
	}
}

// encryptionPipeline processes data through multiple security layers:
// compression -> padding -> first encryption -> second encryption -> Reed-Solomon encoding.
func (tp *TaskProcessor) encryptionPipeline(data []byte) ([]byte, error) {
	// Compress the input data to reduce size
	compressed, err := tp.compressor.Compress(data)
	if err != nil {
		return nil, fmt.Errorf("compression failed: %w", err)
	}

	// Apply PKCS#7 padding to ensure data is compatible with block ciphers
	padded, err := tp.padding.Pad(compressed)
	if err != nil {
		return nil, fmt.Errorf("padding failed: %w", err)
	}

	// First encryption layer using AES-256-GCM
	firstEncrypted, err := tp.firstCipher.Encrypt(padded)
	if err != nil {
		return nil, fmt.Errorf("first encryption (AES-256-GCM) failed: %w", err)
	}

	// Second encryption layer using XChaCha20-Poly1305
	secondEncrypted, err := tp.secondCipher.Encrypt(firstEncrypted)
	if err != nil {
		return nil, fmt.Errorf("second encryption (XChaCha20-Poly1305) failed: %w", err)
	}

	// Apply Reed-Solomon encoding for error correction capabilities
	encoded, err := tp.encoder.Encode(secondEncrypted)
	if err != nil {
		return nil, fmt.Errorf("Reed-Solomon encoding failed: %w", err)
	}

	// Return the fully processed data
	return encoded, nil
}

// decryptionPipeline reverses the encryption process by applying operations
// in reverse order: Reed-Solomon decoding -> second decryption -> first decryption
// -> unpadding -> decompression.
func (tp *TaskProcessor) decryptionPipeline(data []byte) ([]byte, error) {
	// Apply Reed-Solomon decoding to correct any errors and reconstruct data
	decoded, err := tp.encoder.Decode(data)
	if err != nil {
		return nil, fmt.Errorf("Reed-Solomon decoding failed (data may be corrupted): %w", err)
	}

	// First decryption layer (XChaCha20-Poly1305) - reverse second encryption
	firstDecrypted, err := tp.secondCipher.Decrypt(decoded)
	if err != nil {
		return nil, fmt.Errorf("first decryption (XChaCha20-Poly1305) failed - possible tampering detected: %w", err)
	}

	// Second decryption layer (AES-256-GCM) - reverse first encryption
	secondDecrypted, err := tp.firstCipher.Decrypt(firstDecrypted)
	if err != nil {
		return nil, fmt.Errorf("second decryption (AES-256-GCM) failed - possible tampering detected: %w", err)
	}

	// Remove PKCS#7 padding and validate its integrity
	unpadded, err := tp.padding.Unpad(secondDecrypted)
	if err != nil {
		return nil, fmt.Errorf("padding validation failed - possible tampering detected: %w", err)
	}

	// Decompress the data to restore original content
	decompressed, err := tp.compressor.Decompress(unpadded)
	if err != nil {
		return nil, fmt.Errorf("decompression failed - possible data corruption: %w", err)
	}

	// Return the fully restored original data
	return decompressed, nil
}
