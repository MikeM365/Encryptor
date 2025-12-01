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
import hashlib
import secrets
import getpass
from pathlib import Path

# --- Security Constants ---
# SALT_SIZE: 32 bytes ensures unique keys even if passwords are the same.
# ITERATIONS: 100,000 rounds of PBKDF2 slows down Brute Force attacks.

SALT_SIZE = 32
KEY_SIZE = 32
ITERATIONS = 100_000 
BLOCK_SIZE = 64 * 1024  # Process in 64 KB chunks to handle large files efficiently.

def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derives a 32-byte encryption key from a password using PBKDF2.
    
    Why this matters: 
    Simple hashing is vulnerable to Rainbow Table attacks. 
    PBKDF2 adds 'Computational Cost' (Iterations) making it too slow for hackers to brute force.
    """ 
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, ITERATIONS, dklen=KEY_SIZE)
         
def generate_stream_cipher(key: bytes, counter: int) -> bytes:
    """
    Generates a unique keystream for a specific file block.

    Logic:
    We combine the Master Key + Block Number -> SHA256 Hash.
    This creates a unique sequence of pseudo-random bytes to XOR against the data.
    """
     # Create a unique seed for this specific block of the file
    seed = key + counter.to_bytes(8, 'big') 

    # Generate keystream using SHA-256
    keystream = b''
    # We need enough hash bytes to cover the BLOCK_SIZE
    for i in range(BLOCK_SIZE // 32): # 32 bytes per SHA-256 hash output
        hash_input = seed + i.to_bytes(4, 'big')
        keystream += hashlib.sha256(hash_input).digest()

    return keystream[:BLOCK_SIZE]

def encrypt_file(input_file: Path, password: str) -> None:
     """
     Encrypts a file and saves it with a .enc extension.
     """

     # 1. Compliance: Generate a random salt so two files with same password have different keys.
     salt = secrets.token_bytes(SALT_SIZE)

      # 2. Key Management: Derive the key immediately (never store the password).
     key = derive_key(password, salt)

     output_file = Path(str(input_file) + '.enc')

     try:
         with open(input_file, 'rb') as infile:
             with open(output_file, 'wb') as outfile:
                # Write the Salt to the header (needed for decryption)
                 outfile.write(salt)

                 counter = 0
                 while True:
                     # Read chunk
                     chunk = infile.read(BLOCK_SIZE)
                     if not chunk:
                         break

                     # Generate SAME keystream
                     keystream = generate_stream_cipher(key, counter)


                     # XOR Operation
                     encrypted_chunk = bytes(a ^ b for a, b in zip(chunk, keystream[:len(chunk)]))                    

                     # Write encrypted chunk
                     outfile.write(encrypted_chunk)                     
                     counter += 1

         print(f"[SUCCESS] Encrypted: {input_file.name} -> {output_file.name}")

     except IOError as e:
         print(f"[ERROR] File operation failed: {e}")

def decrypt_file(input_file: Path, password: str) -> None:
     """
     Decrypts a file and saves it with a .dec extension.
     """
     # Determine output filename
     if input_file.suffix == '.enc':
        output_file = input_file.with_suffix('')
     else:
        output_file = input_file.with_suffix('.decrypted')

     try:
         with open(input_file, 'rb') as infile:
            # Read the Salt from the header
            salt = infile.read(SALT_SIZE)

            # Derive the key immediately (never store the password).
            key = derive_key(password, salt)

            with open(output_file, 'wb') as outfile:
                 counter = 0
                 while True:
                     # Read chunk
                     chunk = infile.read(BLOCK_SIZE)
                     if not chunk:
                          break

                      # Generate SAME keystream
                     keystream = generate_stream_cipher(key, counter)
                      

                      # XOR Reverse Operation
                     decrypted_chunk = bytes(a ^ b for a, b in
                                            zip(chunk, keystream[:len(chunk)]))

                     outfile.write(decrypted_chunk)
                     counter += 1 

         print(f"[SUCCESS] Decrypted: {input_file.name} -> {output_file.name}")

     except Exception as e:
        print(f"[ERROR] Decryption failed: {e}")

def main():
    """
    Main CLI Interface
    """
    while True:
         print("\n=== Simple Encryptor v1.0 ===")
         print("1. Encrypt a file")
         print("2. Decrypt a file")
         print("3. Exit")

         choice = input("Choose an option: ").strip()
         if choice == '3':
             print("Exiting...")
             sys.exit()

         filename = input("Enter filename: ").strip().replace('"', '')
         file_path = Path(filename)

         if not file_path.exists():
            print(f"[ERROR] File '{filename}' not found.")
            continue

         if choice == '1':
            pwd = getpass.getpass("Set Password: ")
            confirm = getpass.getpass("Confirm Password: ")

            if pwd == confirm:
                encrypt_file(file_path, pwd)
            else:
                print("[ERROR] Passwords did not match.")

         elif choice == '2':
            pwd = getpass.getpass("Enter Password: ")
            decrypt_file(file_path, pwd)

if __name__ == "__main__":
    main()

        

                     
             
   
         
