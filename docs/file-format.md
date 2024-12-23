# Encrypted File Format Specification

This document outlines the file format used for encrypted files in Shifter. When a file is encrypted, it is transformed into this format. Decrypting the file restores it to its original state, as specified prior to encryption.

## Design Goals

- **Security**  
- **Authentication**  
- **Simplicity**  

The main algorithm used to encrypt and decrypt files is **ChaCha20**. This algorithm was chosen because it is simpler to implement than AES and performs faster without hardware acceleration, which is beyond the scope of this project.

For authentication, **HMAC with SHA-256** is used. This choice was made over Poly1305 since HMAC-SHA256 was already implemented for the key derivation algorithm. It produces a 32-byte tag, which is added to the file. This tag is verified before decryption to ensure the correct password is being used or to detect file tampering.

For key derivation, **PBKDF2 with HMAC-SHA256** is used as the PRF. A 32-byte randomly generated salt is included for deriving keys, and the number of iterations is **(TODO: Decide)**. The current iteration count is relatively low due to the lack of hardware acceleration for SHA-256 (or possibly due to inefficiencies in the implementation). 

Two separate keys are derived from the given password:  
1. One for ChaCha20 encryption.  
2. Another for HMAC authentication.  

Each key has its own unique salt to prevent reuse.

## File Structure 

The file format is structured as follows:

1. **4-byte magic number**: `0x53 0x48 0x46 0x54` (e.g., `SHFT` in ASCII) Identifies the file as a Shifter-encrypted file.  
2. **1-byte version number**: Indicates the file format version. Current version is `0x01`.  
3. **32-byte HMAC tag**: Used for file authentication. Ensures the integrity and authenticity of the file.  
4. **32-byte HMAC salt**: Salt for deriving the HMAC key.  
5. **32-byte ChaCha20 salt**: Salt for deriving the ChaCha20 encryption key.  
6. **Ciphertext (variable length)**: The encrypted data, which includes:  
    - The original filename, written as UTF-8 text and null-terminated (filename length is limited to **255 bytes**).
    - The file contents.  
   Both the filename and file contents are encrypted together as a single block using ChaCha20.  

