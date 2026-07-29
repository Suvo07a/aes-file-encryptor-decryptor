import base64
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet


def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,  # high iteration count slows brute-force attempts
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    return key


def encrypt_file(filepath: str, password: str):
    if not os.path.isfile(filepath):
        print("File not found.")
        return

    salt = os.urandom(16)  # random salt, unique per file
    key = derive_key(password, salt)
    fernet = Fernet(key)

    with open(filepath, "rb") as f:
        original_data = f.read()

    encrypted_data = fernet.encrypt(original_data)

    # save salt + encrypted data together — salt is needed again to decrypt
    out_path = filepath + ".enc"
    with open(out_path, "wb") as f:
        f.write(salt + encrypted_data)

    print(f"Encrypted: {out_path}")


def decrypt_file(filepath: str, password: str):
    if not os.path.isfile(filepath):
        print("File not found.")
        return

    with open(filepath, "rb") as f:
        raw = f.read()

    salt = raw[:16]            # first 16 bytes = salt
    encrypted_data = raw[16:]  # rest = actual encrypted content

    key = derive_key(password, salt)
    fernet = Fernet(key)

    try:
        decrypted_data = fernet.decrypt(encrypted_data)
    except Exception:
        print("Decryption failed — wrong key or corrupted file.")
        return

    out_path = filepath.replace(".enc", "") + ".dec"
    with open(out_path, "wb") as f:
        f.write(decrypted_data)

    print(f"Decrypted: {out_path}")


def main():
    print("=== File Encryption & Decryption Tool ===")
    print("1. Encrypt a file")
    print("2. Decrypt a file")
    choice = input("Choose (1/2): ").strip()

    filepath = input("Enter file path: ").strip()
    password = input("Enter secret key: ").strip()

    if choice == "1":
        encrypt_file(filepath, password)
    elif choice == "2":
        decrypt_file(filepath, password)
    else:
        print("Invalid choice.")


if __name__ == "__main__":
    main()
