"""
The Encryptor (Educational Stream Cipher)
Author: Mike McGregor
Purpose: Demonstrates symmetric encryption logic using PBKDF2 key derivation
         and a custom SHA-256 based stream cipher (XOR).

NOTE: This is an educational implementation to demonstrate the mathematics 
      of confidentiality. In a production environment, standard libraries 
      (like AES-GCM via cryptography.io) should be used for compliance.
"""   

import os
import sys
import getpass
from pathlib import Path

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- File Format Constants ---
# MAGIC: Identifies files created by this tool.
# VERSION: Allows future file format changes while preserving compatibility.

MAGIC = b'ENCV2'
VERSION = 1

# --- Cryptographic Settings ---
# SALT_SIZE: Random salt used with scrypt so the same password
#            does not always derive the same key.
# NONCE_SIZE: Unique value used by AES-GCM for each encryption operation.
# KEY_SIZE: 32 bytes = 256-bit AES key.

SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32

# --- Scrypt Work Factors ---
# These parameters make password guessing more expensive.
# N: CPU/memory cost, r and p: tuning parameters for scrypt.

SCRYPT_N = 2**14
SCRYPT_R = 8
SCRYPT_P = 1

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derives a 32-byte encryption key from a password using scrypt.

    Why this matters:
    Passwords are not encryption keys. scrypt strengthens password-based
    encryption by making brute-force guessing slower and more resource-intensive.
    The salt ensures the same password does not always produce the same key.
    """
    kdf = Scrypt(
        salt=salt,
        length=KEY_SIZE,
        n=SCRYPT_N,
        r=SCRYPT_R,
        p=SCRYPT_P,
    )
    return kdf.derive(password.encode("utf-8"))
         
def encrypt_file(input_file: Path, password: str) -> None:
    """
    Encrypts a file and saves it with a .enc extension.
    """

    output_file = Path(str(input_file) + '.enc')

    try:
        # Read the entire file into memory.
        plaintext = input_file.read_bytes()

        # Generate random values for key derivation and encryption.
        salt = os.urandom(SALT_SIZE)
        nonce = os.urandom(NONCE_SIZE)

        # Derive the encryption key from the password and salt.
        key = derive_key(password, salt)
        aesgcm = AESGCM(key)

        # Build a simple file header:
        # [MAGIC][VERSION][SALT][NONCE]
        header = MAGIC + bytes([VERSION]) + salt + nonce

        # Encrypt and authenticate the plaintext.
        ciphertext = aesgcm.encrypt(nonce, plaintext, header)

        with open(output_file, 'wb') as outfile:
            outfile.write(header + ciphertext)

        print(f"[SUCCESS] Encrypted: {input_file.name} -> {output_file.name}")

    except IOError as e:
        print(f"[ERROR] File operation failed: {e}")
    except Exception as e:
        print(f"[ERROR] Encryption failed: {e}")

def decrypt_file(input_file: Path, password: str) -> None:
    """
    Decrypts a file and saves it with the original name or a .decrypted extension.
    """
    if input_file.suffix == '.enc':
        output_file = input_file.with_suffix('')
    else:
        output_file = input_file.with_suffix('.decrypted')

    try:
        file_data = input_file.read_bytes()

        # Header format:
        # [MAGIC][VERSION][SALT][NONCE]
        header_len = len(MAGIC) + 1 + SALT_SIZE + NONCE_SIZE
        header = file_data[:header_len]
        ciphertext = file_data[header_len:]

        # Parse header fields
        magic = header[:len(MAGIC)]
        version = header[len(MAGIC)]
        salt_start = len(MAGIC) + 1
        salt_end = salt_start + SALT_SIZE
        nonce_end = salt_end + NONCE_SIZE

        salt = header[salt_start:salt_end]
        nonce = header[salt_end:nonce_end]

        if magic != MAGIC:
            raise ValueError("Invalid file format.")

        if version != VERSION:
            raise ValueError("Unsupported file version.")

        key = derive_key(password, salt)
        aesgcm = AESGCM(key)

        plaintext = aesgcm.decrypt(nonce, ciphertext, header)

        with open(output_file, 'wb') as outfile:
            outfile.write(plaintext)

        print(f"[SUCCESS] Decrypted: {input_file.name} -> {output_file.name}")

    except Exception:
        print("[ERROR] Decryption failed: wrong password, corrupted file, or invalid file format.")
             

def main():
    """
    Main CLI Interface
    """
    while True:
        print("\n=== Secure Encryptor v2 ===")
        print("1. Encrypt a file")
        print("2. Decrypt a file")
        print("3. Exit")

        choice = input("Choose an option: ").strip()

        if choice == '3':
            print("Exiting...")
            sys.exit()

        if choice not in {'1', '2'}:
            print("[ERROR] Invalid option.")
            continue

        filename = input("Enter filename: ").strip().replace('"', '')
        file_path = Path(filename)

        if not file_path.exists():
            print(f"[ERROR] File '{filename}' not found.")
            continue

        if choice == '1':
            pwd = getpass.getpass("Set Password: ")
            confirm = getpass.getpass("Confirm Password: ")

            if not pwd:
                print("[ERROR] Password cannot be empty.")
                continue

            if pwd == confirm:
                encrypt_file(file_path, pwd)
            else:
                print("[ERROR] Passwords did not match.")

        elif choice == '2':
            pwd = getpass.getpass("Enter Password: ")

            if not pwd:
                print("[ERROR] Password cannot be empty.")
                continue

            decrypt_file(file_path, pwd)


if __name__ == "__main__":
    main()

        

                     
             
   
         
