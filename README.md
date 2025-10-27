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
