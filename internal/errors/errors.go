package errors

import (
	"errors"
)

// Cryptographic operation errors
var (
	// ErrInvalidKey indicates an invalid or malformed encryption key
	ErrInvalidKey = errors.New("invalid encryption key")

	// ErrInvalidKeySize indicates the key size is not supported by AES
	ErrInvalidKeySize = errors.New("AES key must be 16, 24, or 32 bytes")

	// ErrEmptyPlaintext indicates plaintext data is empty or nil
	ErrEmptyPlaintext = errors.New("plaintext cannot be empty")

	// ErrEmptyCiphertext indicates ciphertext data is empty or nil
	ErrEmptyCiphertext = errors.New("ciphertext cannot be empty")

	// ErrEncryptionFailed indicates a general encryption operation failure
	ErrEncryptionFailed = errors.New("encryption operation failed")

	// ErrDecryptionFailed indicates a general decryption operation failure
	ErrDecryptionFailed = errors.New("decryption operation failed")

	// ErrCompressionFailed indicates data compression failed
	ErrCompressionFailed = errors.New("compression operation failed")

	// ErrDecompressionFailed indicates data decompression failed
	ErrDecompressionFailed = errors.New("decompression operation failed")

	// ErrEncodingFailed indicates data encoding failed
	ErrEncodingFailed = errors.New("encoding operation failed")

	// ErrDecodingFailed indicates data decoding failed
	ErrDecodingFailed = errors.New("decoding operation failed")

	// ErrPaddingFailed indicates PKCS#7 padding operation failed
	ErrPaddingFailed = errors.New("padding operation failed")

	// ErrUnpaddingFailed indicates PKCS#7 unpadding operation failed
	ErrUnpaddingFailed = errors.New("unpadding operation failed")
)

// Key derivation errors
var (
	// ErrEmptyPassword indicates the password is empty or nil
	ErrEmptyPassword = errors.New("password cannot be empty")

	// ErrInvalidSalt indicates the salt has invalid length or format
	ErrInvalidSalt = errors.New("invalid salt length")

	// ErrSaltGeneration indicates cryptographically secure salt generation failed
	ErrSaltGeneration = errors.New("failed to generate salt")
)

// File header validation errors
var (
	// ErrInvalidMagic indicates the file header magic bytes are incorrect
	ErrInvalidMagic = errors.New("invalid magic bytes")

	// ErrInvalidHeader indicates the file header format is invalid
	ErrInvalidHeader = errors.New("invalid header format")

	// ErrInvalidNonce indicates the encryption nonce has invalid size
	ErrInvalidNonce = errors.New("invalid nonce size")

	// ErrInvalidIntegrity indicates the integrity hash field has invalid size
	ErrInvalidIntegrity = errors.New("invalid integrity hash size")

	// ErrInvalidAuth indicates the authentication tag has invalid size
	ErrInvalidAuth = errors.New("invalid authentication tag size")

	// ErrChecksumMismatch indicates the header checksum verification failed
	ErrChecksumMismatch = errors.New("header checksum verification failed")

	// ErrIntegrityFailure indicates the header integrity verification failed
	ErrIntegrityFailure = errors.New("header integrity verification failed")

	// ErrAuthFailure indicates the header authentication failed
	ErrAuthFailure = errors.New("header authentication failed")

	// ErrIncompleteWrite indicates not all header bytes were written
	ErrIncompleteWrite = errors.New("incomplete header write")

	// ErrIncompleteRead indicates not all header bytes were read
	ErrIncompleteRead = errors.New("incomplete header read")

	// ErrTampering indicates header tampering was detected
	ErrTampering = errors.New("header tampering detected")

	// ErrEmptyKey indicates an empty authentication key was provided
	ErrEmptyKey = errors.New("authentication key cannot be empty")
)

// File system operation errors
var (
	// ErrFileNotFound indicates the specified file does not exist
	ErrFileNotFound = errors.New("file not found")

	// ErrFileExists indicates the file already exists (prevents overwrite)
	ErrFileExists = errors.New("file already exists")

	// ErrFileEmpty indicates the file has zero bytes
	ErrFileEmpty = errors.New("file is empty")

	// ErrInvalidPath indicates the file path is invalid or malformed
	ErrInvalidPath = errors.New("invalid file path")

	// ErrFileCreateFailed indicates file creation failed
	ErrFileCreateFailed = errors.New("failed to create file")

	// ErrFileOpenFailed indicates file opening failed
	ErrFileOpenFailed = errors.New("failed to open file")

	// ErrFileReadFailed indicates file reading failed
	ErrFileReadFailed = errors.New("failed to read file")

	// ErrFileWriteFailed indicates file writing failed
	ErrFileWriteFailed = errors.New("failed to write file")

	// ErrSecureDeleteFailed indicates secure file deletion failed
	ErrSecureDeleteFailed = errors.New("secure deletion failed")
)

// Stream processing errors
var (
	// ErrNilStream indicates input/output streams are nil
	ErrNilStream = errors.New("input and output streams must not be nil")

	// ErrCanceled indicates the operation was canceled by user/context
	ErrCanceled = errors.New("operation was canceled")

	// ErrChunkTooLarge indicates a data chunk exceeds maximum allowed size
	ErrChunkTooLarge = errors.New("chunk size exceeds maximum allowed")
)

// Authentication errors
var (
	// ErrPasswordMismatch indicates password confirmation doesn't match
	ErrPasswordMismatch = errors.New("passwords do not match")
)

// User interface errors
var (
	// ErrUserCanceled indicates the user canceled the operation
	ErrUserCanceled = errors.New("operation canceled by user")

	// ErrNoFilesAvailable indicates no files are available for selection
	ErrNoFilesAvailable = errors.New("no files available for selection")

	// ErrPromptFailed indicates a user prompt operation failed
	ErrPromptFailed = errors.New("user prompt failed")
)
