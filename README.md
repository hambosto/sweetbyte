
<div align="center">

```
███████╗██╗    ██╗███████╗███████╗████████╗██████╗ ██╗   ██╗████████╗███████╗
██╔════╝██║    ██║██╔════╝██╔════╝╚══██╔══╝██╔══██╗╚██╗ ██╔╝╚══██╔══╝██╔════╝
███████╗██║ █╗ ██║█████╗  █████╗     ██║   ██████╔╝ ╚████╔╝    ██║   █████╗  
╚════██║██║███╗██║██╔══╝  ██╔══╝     ██║   ██╔══██╗  ╚██╔╝     ██║   ██╔══╝  
███████║╚███╔███╔╝███████╗███████╗   ██║   ██████╔╝   ██║      ██║   ███████╗
╚══════╝ ╚══╝╚══╝ ╚══════╝╚══════╝   ╚═╝   ╚═════╝    ╚═╝      ╚═╝   ╚══════╝
```

**A resilient, secure, and efficient file encryption tool.**

</div>

---

### Table of Contents
- [Why SweetByte?](#-why-sweetbyte)
- [Core Features](#-core-features)
- [How It Works: The Encryption Pipeline](#-how-it-works-the-encryption-pipeline)
- [File Format](#-file-format)
- [Usage](#-usage)
- [Building from Source](#️-building-from-source)
- [Internal Packages Overview](#-internal-packages-overview)
- [Contributing](#-contributing)
- [License](#-license)

---

**SweetByte** is a high-security file encryption tool designed for robustness and performance. It safeguards your files using a multi-layered cryptographic pipeline, ensures data integrity with error correction codes, and provides a seamless user experience with both interactive and command-line interfaces.

## 🤔 Why SweetByte?

SweetByte was built with three core principles in mind:

- **Security First:** Security is not just a feature; it's the foundation. By layering best-in-class cryptographic primitives like **AES-256**, **XChaCha20**, and **Argon2id**, SweetByte provides defense-in-depth against a wide range of threats.
- **Extreme Resilience:** Data corruption can render encrypted files useless. SweetByte tackles this head-on by integrating **Reed-Solomon error correction**, giving your files a fighting chance to survive bit rot, transmission errors, or physical media degradation.
- **User-Centric Design:** Powerful security tools should be accessible. With both a guided **interactive mode** for ease of use and a powerful **CLI** for automation, SweetByte caters to all workflows without compromising on functionality.

## ✨ Core Features

- **Dual-Algorithm Encryption:** Chains **AES-256-GCM** and **XChaCha20-Poly1305** for a layered defense, combining the AES standard with the modern, high-performance ChaCha20 stream cipher.
- **Strong Key Derivation:** Utilizes **Argon2id**, the winner of the Password Hashing Competition, to protect against brute-force attacks on your password.
- **Resilient File Format:** Integrates **Reed-Solomon error correction codes**, which add redundancy to the data. This allows the file to be successfully decrypted even if it suffers from partial corruption.
- **Tamper-Proof File Header:** Each encrypted file includes a secure header with multiple layers of verification:
    - **HMAC-SHA256 Authentication Tag:** Ensures the header has not been tampered with by an attacker.
    - **SHA-256 Integrity Hash:** Verifies the structural integrity of the header's metadata.
    - **CRC32 Checksum:** Provides a fast check against accidental data corruption.
- **Efficient Streaming:** Processes files in concurrent chunks, ensuring low memory usage and high throughput, even for very large files.
- **Dual-Mode Operation:**
    - **Interactive Mode:** A user-friendly, wizard-style interface that guides you through every step.
    - **Command-Line (CLI) Mode:** A powerful and scriptable interface for automation and power users.
- **Secure Deletion:** Offers an option to securely wipe source files after an operation by overwriting them with random data, making recovery nearly impossible.

## ⚙️ How It Works: The Encryption Pipeline

SweetByte processes data through a sophisticated pipeline to ensure confidentiality, integrity, and resilience.

```
Original Data ➔ [Compression] ➔ [Padding] ➔ [AES Encrypt] ➔ [XChaCha20 Encrypt] ➔ [Reed-Solomon Encode] ➔ Encrypted File
```

#### Encryption Flow
When encrypting a file, the data passes through the following stages:

1.  **Zlib Compression:** The raw data is compressed to reduce its size.
2.  **PKCS7 Padding:** The compressed data is padded to a specific block size, a prerequisite for block ciphers.
3.  **AES-256-GCM Encryption:** The padded data is encrypted with AES, the industry standard.
4.  **XChaCha20-Poly1305 Encryption:** The AES-encrypted ciphertext is then encrypted *again* with XChaCha20, adding a second, distinct layer of security.
5.  **Reed-Solomon Encoding:** The final ciphertext is encoded with error correction data, making it resilient to corruption.

This multi-stage process results in a final file that is not only encrypted but also compressed and fortified against data rot.

#### Decryption Flow
Decryption is the exact reverse of the encryption pipeline, unwrapping each layer to securely restore the original data.

## 📦 File Format

Encrypted files (`.swb`) have a custom binary structure designed for security and efficiency.

#### Overall Structure
An encrypted file consists of a fixed-size header followed by a series of variable-length data chunks.

```
[ Secure Header (128 bytes) ] [ Chunk 1 ] [ Chunk 2 ] ... [ Chunk N ]
```

#### Secure Header (128 bytes)
The header contains all the metadata required to decrypt the file.

| Field           | Size (bytes) | Description                                           |
| --------------- | ------------ | ----------------------------------------------------- |
| **Magic Bytes** | 4            | `HWX2` - Identifies the file as a SweetByte file.     |
| **Salt**        | 32           | A unique, random salt for the Argon2id key derivation.|
| **Original Size**| 8            | The size of the original, unencrypted file.           |
| **Nonce**       | 16           | A unique nonce for the AEAD encryption.               |
| **Integrity Hash**| 32           | A SHA-256 hash to verify header structural integrity. |
| **Auth Tag**    | 32           | An HMAC-SHA256 tag to authenticate the header.        |
| **Checksum**    | 4            | A CRC32 checksum to detect accidental corruption.     |

#### Cryptographic Parameters
SweetByte uses strong, modern cryptographic parameters for key derivation and encryption.

- **Argon2id Parameters:**
    - **Time Cost:** 3
    - **Memory Cost:** 64 MB
    - **Parallelism:** 4 threads
- **Reed-Solomon Parameters:**
    - **Data Shards:** 4
    - **Parity Shards:** 10 (Provides high redundancy)

#### Data Chunks
Following the header, the file contains the encrypted data, split into chunks. Each chunk is prefixed with a 4-byte length header, which is essential for the streaming-based decryption process.

```
[ Chunk Size (4 bytes) ] [ Encrypted & Encoded Data (...) ]
```

## 🚀 Usage

#### Installation
To install SweetByte, use the `go install` command:
```sh
go install github.com/hambosto/sweetbyte@latest
```

#### Interactive Mode
For a guided experience, run SweetByte without any commands. This is the default mode.
```sh
sweetbyte
```
You can also explicitly run interactive mode:
```sh
sweetbyte interactive
```
The interactive prompt will guide you through selecting an operation (encrypt/decrypt), choosing a file, and handling the source file after the operation is complete.

#### Command-Line (CLI) Mode
For scripting and automation, use the `encrypt` and `decrypt` commands.

**To Encrypt a File:**
```sh
# Basic encryption (will prompt for password)
sweetbyte encrypt -i my_document.txt -o my_document.swb

# Provide a password and delete the original file after encryption
sweetbyte encrypt -i my_document.txt -p "my-secret-password" --delete-source
```

**To Decrypt a File:**
```sh
# Basic decryption (will prompt for password)
sweetbyte decrypt -i my_document.swb -o my_document.txt

# Provide a password and securely delete the encrypted source file
sweetbyte decrypt -i my_document.swb -p "my-secret-password" --delete-source --secure-delete
```

## 🏗️ Building from Source

To build the project from source, clone the repository and use the `go build` command.

```sh
git clone https://github.com/hambosto/sweetbyte.git
cd sweetbyte
go build .
```

## 🏛️ Internal Packages Overview

SweetByte is built with a modular architecture, with each package handling a specific responsibility.

| Package           | Description                                                              |
| ----------------- | ------------------------------------------------------------------------ |
| `cipher`          | Implements the AES and XChaCha20-Poly1305 encryption algorithms.         |
| `cli`             | Contains the command-line interface logic using the Cobra library.       |
| `compression`     | Handles Zlib compression and decompression.                              |
| `config`          | Stores all application-wide constants and configuration parameters.      |
| `encoding`        | Manages Reed-Solomon error correction encoding and decoding.             |
| `errors`          | Defines custom, descriptive error types used throughout the application. |
| `files`           | Provides utilities for finding, managing, and securely deleting files.   |
| `flow`            | Orchestrates the main encryption/decryption pipeline.                    |
| `header`          | Manages the serialization, deserialization, and verification of the secure file header. |
| `interactive`     | Implements the user-friendly interactive mode workflow.                  |
| `keys`            | Handles key derivation using Argon2id and secure salt generation.        |
| `operations`      | Contains the high-level logic for the main encrypt/decrypt file operations. |
| `padding`         | Implements PKCS7 padding.                                                |
| `streaming`       | Manages concurrent, chunk-based file processing with a worker pool.      |
| `types`           | Defines core data structures and types used across the project.          |
| `ui`              | Provides UI components like interactive prompts, progress bars, and banners. |
| `utils`           | Contains miscellaneous helper functions.                                 |

## 🤝 Contributing

Contributions are welcome! If you'd like to contribute, please feel free to fork the repository and submit a pull request. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate and run the quality checks before submitting your contribution.

## 📜 License

This project is licensed under the [MIT License](LICENSE).
