# Encryption Tool

A simple file encryption/decryption tool built with Python using Fernet symmetric encryption.

## Description
This tool allows users to securely encrypt and decrypt messages/files using the cryptography library's Fernet implementation. Fernet guarantees that a message encrypted using it cannot be manipulated or read without the key.

## Features
- Generate encryption keys
- Encrypt messages with strong symmetric encryption
- Decrypt messages with the correct key
- Key management (save/load encryption keys)
- User-friendly command-line interface

## Requirements
- Python 3.x
- cryptography library

## Installation
```bash
pip install cryptography

Follow the prompts to:

Generate a new encryption key (first time use)
Enter a message to encrypt
Decrypt messages using the saved key
How it Works
Uses Fernet symmetric encryption (AES 128-bit in CBC mode)
Generates secure random keys
Keys are saved locally for future use
Each encrypted message includes authentication to prevent tampering
Security Note
Keep your encryption key file (key.key) secure and private
Anyone with access to the key file can decrypt your messages
This tool is for educational purposes
Author
[Your Name]
