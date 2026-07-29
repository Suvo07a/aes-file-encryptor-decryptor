import base64
import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes


# ---------------- CORE AES LOGIC ----------------

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=16,          # 16 bytes = AES-128
        salt=salt,
        iterations=390000,
    )
    return kdf.derive(password.encode())


def encrypt_file(filepath: str, password: str):
    salt = os.urandom(16)
    iv = os.urandom(16)          # AES-CBC needs a random IV each time
    key = derive_key(password, salt)

    with open(filepath, "rb") as f:
        original_data = f.read()

    # AES works on fixed-size blocks, so pad data to a multiple of 16 bytes
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(original_data) + padder.finalize()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    out_path = filepath + ".enc"
    with open(out_path, "wb") as f:
        f.write(salt + iv + encrypted_data)   # store salt + iv alongside ciphertext

    return out_path


def decrypt_file(filepath: str, password: str):
    with open(filepath, "rb") as f:
        raw = f.read()

    salt = raw[:16]
    iv = raw[16:32]
    encrypted_data = raw[32:]

    key = derive_key(password, salt)

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    unpadder = padding.PKCS7(128).unpadder()
    original_data = unpadder.update(padded_data) + unpadder.finalize()

    out_path = filepath.replace(".enc", "") + ".dec"
    with open(out_path, "wb") as f:
        f.write(original_data)

    return out_path


# ---------------- GUI ----------------

selected_file = None


def browse_file():
    global selected_file
    path = filedialog.askopenfilename(title="Select a file")
    if path:
        selected_file = path
        file_label.config(text=os.path.basename(path))


def handle_encrypt():
    if not selected_file:
        messagebox.showerror("Error", "No file selected.")
        return
    password = password_entry.get()
    if not password:
        messagebox.showerror("Error", "Enter a secret key.")
        return
    try:
        out_path = encrypt_file(selected_file, password)
        messagebox.showinfo("Success", f"Encrypted (AES-256):\n{out_path}")
    except Exception as e:
        messagebox.showerror("Error", str(e))


def handle_decrypt():
    if not selected_file:
        messagebox.showerror("Error", "No file selected.")
        return
    password = password_entry.get()
    if not password:
        messagebox.showerror("Error", "Enter a secret key.")
        return
    try:
        out_path = decrypt_file(selected_file, password)
        messagebox.showinfo("Success", f"Decrypted:\n{out_path}")
    except Exception:
        messagebox.showerror("Error", "Decryption failed — wrong key or corrupted file.")


# ---------------- WINDOW SETUP ----------------

root = tk.Tk()
root.title("AES File Encryption & Decryption Tool")
root.geometry("420x260")
root.resizable(False, False)

tk.Label(root, text="AES File Encryption & Decryption Tool", font=("Arial", 13, "bold")).pack(pady=12)

tk.Button(root, text="Select File", command=browse_file, width=20).pack(pady=5)
file_label = tk.Label(root, text="No file selected", fg="gray")
file_label.pack()

tk.Label(root, text="Secret Key:").pack(pady=(15, 0))
password_entry = tk.Entry(root, show="*", width=30)
password_entry.pack(pady=5)

btn_frame = tk.Frame(root)
btn_frame.pack(pady=20)

tk.Button(btn_frame, text="Encrypt", command=handle_encrypt, width=12, bg="#2e7d32", fg="white").pack(side="left", padx=10)
tk.Button(btn_frame, text="Decrypt", command=handle_decrypt, width=12, bg="#1565c0", fg="white").pack(side="left", padx=10)

root.mainloop()
