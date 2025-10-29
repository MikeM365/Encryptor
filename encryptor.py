"""

Simple Encryptor - Password-based file encryption tool
"""

import os
import sys
import hmac
import hashlib
import secrets
import getpass
import struct
from typing import Tuple, Optional
from pathlib import Path

#Security constants
SALT_SIZE = 32
KEY_SIZE = 32
ITERATIONS = 100000 # Number of iterations for PBKDF2
BLOCK_SIZE = 64 * 1024  # 64 KB

def derive_key(password: str, salt: bytes) -> bytes:
    """

    Derive encryption key from a password using PBKDF2 

    Args:
        password: User's password
        salt: Random salt for this encryption

    Returns:
        32 byte encryption key

    """ 
    return hashlib.pbkdf2_hmac('sha256', password.encode(), salt, ITERATIONS, dklen=KEY_SIZE)

def generate_stream_cipher(key: bytes, counter: int = 0) -> bytes:
    """
    Generate a stream cipher using key and counter 
    Creates unique keystream for each 64 KB chunk

    Args:
        key: 32 byte encryption key from derive_key()
        counter: Block number (increments for each chunk)

    Returns:
        64kbs of keystream bytes for XOR encryption
    """
  #Create a unique seed for this block
    seed = key + counter.to_bytes(8, 'big')

    #Generate keystream using SHA-256
    keystream = b''
    for i in range(BLOCK_SIZE // 32): #32 bytes per SHA-256 hash
        hash_input = seed + i.to_bytes(4, 'big')
        keystream += hashlib.sha256(hash_input).digest()

    return keystream[:BLOCK_SIZE]

def encrypt_file(input_file: Path, output_file: Path, password: str) -> None:
     """
     
     Encrypt a file using password based encryption

     Arges:
          filepath: Path to file to encrypt
          password: User's password

     """
     #Generate random salt for this encrption
     salt = secrets.token_bytes(SALT_SIZE)

     #Derive encryption key from password and salt
     key = derive_key(password, salt)

     #Create output filename (add .enc extension)
     output_file = Path(str(input_file) + '.enc' )

     #Open input file and create output file
     with open(input_file, 'rb') as infile:
         with open(output_file, 'wb') as outfile:
             #First, write the salt to the output file
             #(We need it for decryption!)
             outfile.write(salt)

             #Process the file chunk by chunk
             counter = 0
             while True:
                 #Read a chunk of data from the input file
                 chunk = infile.read(BLOCK_SIZE)
                 if not chunk:
                     break

                 #Generate a keystream for this chunk
                 keystream = generate_stream_cipher(key, counter)

                 #XOR the chunk with the keystream
                 encrypted_chunk = bytes(a ^ b for a, b in 
                                       zip(chunk,keystream[:len(chunk)]))

                 #Write the encrypted chunk
                 outfile.write(encrypted_chunk)
                 counter  += 1

     #Print success message
     print(f"Encrypted: {input_file} -> {output_file}")


    
                        
def decrypt_file(input_file: Path, output_file: Path, password: str) -> None:
    """
    Decrypt a file encrypted with encrypt_file()

    Args:
     input_file: Path to encrypted file (should end in .enc)
     output_file: Path to decrypted file
      password: User's password
    """
    #Open input file and create output file
    with open(input_file, 'rb') as infile:
        #First, read the salt (the first 32 bytes of the file) 
        salt = infile.read(SALT_SIZE)

        #Derive the same key using password + salt
        key = derive_key(password, salt)

        with open(output_file, 'wb') as outfile:
             #Process the file chunk by chunk
             counter = 0
             while True:
                  #Read a chunk of data from the input file
                  chunk = infile.read(BLOCK_SIZE)
                  if not chunk:
                       break

                  #Generate the same keystream as during encryption
                  keystream = generate_stream_cipher(key, counter)

                  #XOR again to decrypt (same operation as encryption)
                  decrypted_chunk = bytes(a ^ b for a, b in
                                        zip(chunk, keystream[:len(chunk)]))
                  
                  #Write the decrypted chunk
                  outfile.write(decrypted_chunk)
                  counter += 1

    #Print success message
    print(f"Decrypted: {input_file} -> {output_file}")

def main():
    """
    Main function -handeles user interaction and argument parsing
    """
    print("Simple Encryptor v1.0")
    print("-" * 30)

    #Get user's choice
    print("Encryt a file")
    print("Decrypt a file")
    print("Exit")

    choice = input("Enter your choice (1/2/3): ").strip()

    if choice == '1':
         #Encrypt a file
        filename = input("Enter the filename to encrypt: ").strip()
        input_file = Path(filename)

        if not input_file.exists():
            print("Error: {filename} not found!")
            
        password = getpass.getpass("Enter password: ")
        confirm = getpass.getpass("Confirm password: ")

        if password != confirm:
            print("Passwords do not match!")
            return

        encrypted_file = Path(str(input_file) + '.enc')
        encrypt_file(input_file, encrypted_file, password) #Now matches function parameters!

    elif choice == '2':
        #Decrypt mode
         filename = input("Enter the filename to decrypt: ").strip()
         input_file = Path(filename)

         if not input_file.exists():
              print("Error: {filename} not found!")
              return

         if not  input_file.name.endswith('.enc'):
              print("Warning: Filename does not have .enc extension")
              proceed = input("Do you want to proceed? (y/n): ").strip().lower()
              if  proceed != 'y':
                  return
              

         password = getpass.getpass("Enter password: ")

         #Create output filename (remove .enc extension)
         if  input_file.name.endswith('.enc'):
              output_file = Path(input_file.name[:-4]) #Remove last four chars (.enc)
         else:
              output_file = Path(input_file.name + '.decrypted')
             
         try:
             decrypt_file(input_file, output_file, password)
         except Exception as e:
              print(f"Decryption failed: {e}")
              print("Wrong password or corrupted file?")

if __name__ == "__main__":
    main()
             
     
                                          

       
        



    
     
  


