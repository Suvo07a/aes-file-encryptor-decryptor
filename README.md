# AES File Encryption & Decryption Tool

A Python tool that encrypts and decrypts files using AES-128, protecting them with a user-defined secret key. Includes both a command-line version and a Tkinter GUI version.

## Features

- Encrypt any file type (documents, images, PDFs, archives)
- Decrypt previously encrypted files back to their original form
- User-defined secret key — nothing is stored, only you can decrypt
- AES-128 in CBC mode with PKCS7 padding
- Key derivation via PBKDF2 (SHA-256, 390,000 iterations) — turns a plain password into a proper 128-bit AES key, with a random salt per file
- Simple Tkinter GUI: pick a file, enter a key, click Encrypt or Decrypt
- CLI version available for terminal-only use

## How it works

1. User selects a file and enters a secret key
2. A random salt and IV (initialization vector) are generated for that file
3. The secret key + salt are run through PBKDF2 to derive a 128-bit AES key
4. The file is padded to a multiple of 16 bytes (AES block size) and encrypted using AES-128-CBC
5. The salt, IV, and encrypted data are saved together as `filename.enc`
6. To decrypt: the same secret key re-derives the same AES key using the stored salt, and the file is decrypted and unpadded back to its original bytes

```python
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
encryptor = cipher.encryptor()
encrypted_data = encryptor.update(padded_data) + encryptor.finalize()
```

## Files

- `file_crypt.py` — command-line version
- `file_crypt_gui.py` — Tkinter GUI version

## Usage

```bash
python3 -m venv venv
source venv/bin/activate
pip install cryptography
```

### GUI version
```
python3 file_crypt_gui.py
```
Select a file, enter a secret key, click **Encrypt** or **Decrypt**.

### CLI version
```bash
python3 file_crypt.py
```
Follow the prompts to choose encrypt/decrypt, provide a file path, and enter your secret key.

## Tech stack

- Python 3
- `cryptography` library (AES, PBKDF2)
- Tkinter (GUI)

## Security notes

- The secret key is never stored anywhere — if forgotten, the encrypted file cannot be recovered
- Each file gets a unique random salt and IV, so encrypting the same file twice with the same key produces different ciphertext
- This tool is for learning/personal use; production systems should also add integrity verification (e.g. HMAC or authenticated encryption modes like AES-GCM)

## License

MIT
