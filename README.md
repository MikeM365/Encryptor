# Encryption Tool

A password-based file encryption/decryption tool built with Python using scrypt key derivation and AES-256-GCM authenticated encryption.

## Description

This tool encrypts and decrypts files using a password you supply. Scrypt (a memory-hard key derivation function) turns that password into a 256-bit key, and AES-256-GCM both encrypts the file and authenticates it — so any tampering with the encrypted file, including its header, causes decryption to fail rather than silently succeeding.

## Features

- Derive an encryption key from a password using scrypt
- Encrypt files with AES-256-GCM authenticated encryption
- Decrypt files with the correct password
- Unique random salt and nonce generated per file, so the same password never produces identical ciphertext twice
- Versioned, tamper-evident file format
- Command-line interface

## Requirements

- Python 3.x
- `cryptography` library

## Installation

Install the dependency with `pip install cryptography`, then run the script and follow the prompts to encrypt or decrypt a file.

## How It Works

- Scrypt derives a 256-bit key from your password and a randomly generated salt
- AES-256-GCM encrypts the file contents and authenticates both the ciphertext and the file header
- A fresh salt and nonce are generated for every encryption operation

## Security Note

This is password-based — there's no key file to protect, but there's also no recovery if you forget the password. Built for educational purposes to demonstrate authenticated symmetric encryption.

## Author

Mike McGregor
