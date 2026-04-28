#!/usr/bin/env python3

# Simple AES-GCM file encryption/decryption tool.
# The user provides a password, which is converted into an AES-256 key using PBKDF2.
# The encrypted file stores a small header containing the salt flag, optional salt, and ciphertext.

import os
import sys
import getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

# Cryptographic parameter sizes, measured in bytes.
# AES-GCM commonly uses a 12-byte nonce/IV.
# A 32-byte key means AES-256
# PBKDF2 iterations slow down brute-force password guessing.

SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
ITERATIONS = 100000

BANNER = r"""
01000001 01000101 01010011
  _____ _   _  ____ ____  __   __ ____ _____ 
 | ____| \ | |/ ___|  _ \ \ \ / /|  _ \_   _|
 |  _| |  \| | |   | |_) | \ V / | |_) || |  
 | |___| |\  | |___|  _ <   | |  |  __/ | |  
 |_____|_| \_|\____|_| \_\  |_|  |_|    |_|  

=============================================
          AES-GCM FILE ENCRYPTOR
=============================================
Mode: Encrypt/Decrypt
KDF: PBKDF2-HMAC-SHA256
Auth: AES-GCM Tag Verification
=============================================
"""

def derive_key(password, salt):

    """
    Derive a 256-bit AES key from the user's password and salt.
    The same password and salt must be used during decryption to recreate the key.
    """

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode())

def encrypt_file(input_file, output_file, password, use_salt=True):

    # Generate a random salt unless the user selected --nosalt.
    # The salt is not secret, but it makes password-derived keys harder to precompute.
    # Generate a fresh nonce/IV for AES-GCM. The nonce must be unique for each encryption.
    # Derive the AES key from password and salt.

    salt = os.urandom(SALT_SIZE) if use_salt else b""
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)

    # Read the input file as raw byte so any file type can be encrypted.
    # AES-GCM encrypts the data and also creates an authentication tag to detect tampering.

    data = open(input_file, "rb").read()
    encrypted = AESGCM(key).encrypt(nonce, data, None)

    # Write the encrypted output in this custom format:
    # [1-byte salt flag] [optional salt] [nonce/IV] [ciphertext + authentication tag]
    # This allows the decrypt function to know how to rebuild the key decrypt the file.

    with open(output_file, "wb") as f:
        f.write(b"\x01" if use_salt else b"\x00")
        if use_salt:
            f.write(salt)
        f.write(nonce)
        f.write(encrypted)

    print("File encrypted.")
    print("Output file:", output_file)

    # WARNING: Printing the key is useful for learning/debugging.
    # Real encryption tools should never display or log secret keys.

    print("Key:", key.hex())
    print("IV:", nonce.hex())
    if use_salt:
        print("Salt:", salt.hex())
    else:
        print("Salt: None")

def decrypt_file(input_file, output_file, password):

    """
    Read the encrypted file, parse the stored salt and nonce,
    derive the same AES key, and decrypt the ciphertext.
    """

    data = open(input_file, "rb").read()

    # The first byte tells us whther a salt was stored during encryption.
    # pos tracks where we are while parsing the encrypted file structure.

    use_salt = data[0] == 1
    pos = 1

    if use_salt:
        salt = data[pos:pos + SALT_SIZE]
        pos += SALT_SIZE
    else:
        salt = b""

    # After the optional salt, the next bytes are the AES-GCM nonce/IV.
    # Everything after the nonce is the ciphertext plus the authentication tag.

    nonce = data[pos:pos + NONCE_SIZE]
    pos += NONCE_SIZE
    ciphertext = data[pos:]

    key = derive_key(password, salt)

    print("Key:", key.hex())
    print("IV:", nonce.hex())
    if use_salt:
        print("Salt:", salt.hex())
    else:
        print("Salt: None")

    # AES-GCM verifies the authentication tag during decryption.
    # If the password is wrong or the file was modified, this will raise InvalidTag.

    decrypted = AESGCM(key).decrypt(nonce, ciphertext, None)

    with open(output_file, "wb") as f:
        f.write(decrypted)

# Command-line interface for the script.
# Expected usage:
    # python3 aes_gcm.py encrypt input.txt output.enc [--nosalt]
    # python3 aes_gcm.py decrypt input.enc output.txt

if __name__ == "__main__":
    print(BANNER)
    if len(sys.argv) not in (4, 5) or sys.argv[1] not in ["encrypt", "decrypt"]:
        print("Usage:")
        print(" python3 aes_gcm.py encrypt input.txt output.enc [--nosalt]")
        print(" python3 aes_gcm.py decrypt input.enc output.txt")
        sys.exit(1)

    mode, input_file, output_file = sys.argv[1], sys.argv[2], sys.argv[3]
    
    # Prompt for the password without displaying it in the terminal.

    password = getpass.getpass("Password: ")

    if mode == "encrypt":

        # --nosalt is included for demonstration/testing.
        # In normal use, salitng should remain enabled.

        use_salt = "--nosalt" not in sys.argv
        encrypt_file(input_file, output_file, password, use_salt)
    elif mode == "decrypt":
        try:
            decrypt_file(input_file, output_file, password)
            print("File decrypted.")
            print("Output file:", output_file)
        except InvalidTag:
            print("Decryption failed. Incorrect password or corrupted file.")
            sys.exit(1)
    else:
        print("First argument must be encrypt or decrypt")
        sys.exit(1)