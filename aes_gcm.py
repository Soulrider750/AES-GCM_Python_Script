#!/usr/bin/env python3

import os
import sys
import getpass
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
ITERATIONS = 100000

def derive_key(password, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=ITERATIONS,
    )
    return kdf.derive(password.encode())

def encrypt_file(input_file, output_file, password, use_salt=True):
    salt = os.urandom(SALT_SIZE) if use_salt else b""
    nonce = os.urandom(NONCE_SIZE)
    key = derive_key(password, salt)

    data = open(input_file, "rb").read()
    encrypted = AESGCM(key).encrypt(nonce, data, None)

    with open(output_file, "wb") as f:
        f.write(b"\x01" if use_salt else b"\x00")
        if use_salt:
            f.write(salt)
        f.write(nonce)
        f.write(encrypted)

    print("File encrypted.")
    print("Output file:", output_file)
    print("Key:", key.hex())
    print("IV:", nonce.hex())
    if use_salt:
        print("Salt:", salt.hex())
    else:
        print("Salt: None")

def decrypt_file(input_file, output_file, password):
    data = open(input_file, "rb").read()

    use_salt = data[0] == 1
    pos = 1

    if use_salt:
        salt = data[pos:pos + SALT_SIZE]
        pos += SALT_SIZE
    else:
        salt = b""

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
        
    decrypted = AESGCM(key).decrypt(nonce, ciphertext, None)

    with open(output_file, "wb") as f:
        f.write(decrypted)

if __name__ == "__main__":
    if len(sys.argv) not in (4, 5) or sys.argv[1] not in ["encrypt", "decrypt"]:
        print("Usage:")
        print(" python3 aes_gcm.py encrypt input.txt output.enc [--nosalt]")
        print(" python3 aes_gcm.py decrypt input.enc output.txt")
        sys.exit(1)

    mode, input_file, output_file = sys.argv[1], sys.argv[2], sys.argv[3]
    password = getpass.getpass("Password: ")

    if mode == "encrypt":
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