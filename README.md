## AES-GCM File Encryptor / Decryptor ##

A simple Python script created by me for encrypting and decrypting files with **AES-GCM** using the `cryptography` library.

This tool uses a password to derive a 256-bit key with **PBKDF2-HMAC-SHA256**, then decrypts file contents using **AES-GCM**. 
It also displays the derived key, IV, and salt in the terminal during both encryption and decryption. This script supports encryption with a random salt by default, or without a salt by using the `--nosalt` option.

## Features ##

- Encrypt files with AES-GCM
- Decrypt files encrypted by the script
- Password-based key derivation using the PBKDF2-HMAC-SHA256
- 256-bit AES key length
- Random 12-byte IV / nonce generation
- Optional `--nosalt` mode
- Displays:
  - Output file name
  - Derived key
  - IV/nonce
  - Salt status

## Requirements ##

- Python 3
- `cryptography` library

## Installation ##

Clone the repository and install the required dependency:

If you are on a Mac:

```bash
pip3 install cryptography
```
Otherwise:
```bash
pip install cryptography
```

## Usage ##

Encrypt a file

```bash
python3 aes_gcm.py encrypt input.txt output.enc
```

Encrypt a file without salt

```bash
python3 aes_gcm.py encrypt input.txt output.enc --nosalt
```

Decrypt a file
```bash
python3 aes_gcm.py decrypt output.enc decrypted.txt
```

## Example Output ##

Encryption

```bash
Password:
File encrypted
Output file: output.enc
Key: <derived key in hex>
IV: <iv in hex>
Salt: <salt in hex>
```

Decryption

```bash
Password:
Key: <derived key in hex>
IV: <iv in hex>
Salt: <salt in hex>
File decrypted.
Output file: decrypted.txt
```
If the wrong password is entered, or the encrypted file has been modified or corrupted, the script will display:
```bash
Decryption failed. Incorrect password or corrupted file.
```

## How it works ##

When encrypting a file, the script:

1. Prompts the user for a password.
2. Generates either:
   - a random 16-byte salt, or
   - no salt if `--nosalt` is used
3. Derives a 32-byte AES key using PBKDF2-HMAC-SHA256
4. Generates a random 12-byte IV/nonce
5. Encrypts the file with AES-GCM
6. Writes the encrypted output in this format:
```bash
[1 byte salt flag][optional salt][12 byte nonce][ciphertext]
```
When decrypting, the script reads that structure back, rebuilds the key from the password and salt settings, and attempts to decrypt the file. 

## File Format ##

The ecrypted output file contains:
- 1 byte: salt usage flag
  - `0x01` = salt used
  - `0x00` = no salt
- 16 bytes: salt, if enabled
- 12 bytes: AES-GCM nonce/IV
- remaining bytes: ciphertext and authentication tag

## Security Notes ##

This project is intended to be a simple educational file encryption tool.

A few important notes:

- AES-GCM provides both confidentiality and integrity.
- Reusing an IV with the same key in AES-GCM is unsafe.
- Using a salt is more secure than `--nosalt` for password-based key derivation.
- Printing the derived key to the terminal is useful for learning and debugging, but is not recommended for real-world security tools.
- This script reads the full file into memory, so it is better suited for small to medium files.

## Script Name ## 
If your file is named differently, update the commands in this README accordingly. The examples above assume the script is named:
```bash
aes_gcm.py
```

## Disclaimer ##

This project is for educational and demonstration purposes. It should not be treated as a production-ready utility without additional hardening, validation, and security review.
