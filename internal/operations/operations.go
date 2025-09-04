// Package operations provides high-level encryption and decryption operations.
package operations

// Encryptor defines the interface for file encryption.
type Encryptor interface {
	EncryptFile(srcPath, destPath, password string) error
}

// Decryptor defines the interface for file decryption.
type Decryptor interface {
	DecryptFile(srcPath, destPath, password string) error
}
