
import os
import json
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import ipfshttpclient
from ecies import encrypt as ecies_encrypt

# ------------------ تنظیمات اولیه ------------------

RECIPIENTS = [
    {
        "address": "0xRecipientAddress1",
        "pubkey_hex": "04ffeedd..."  # uncompressed public key
    },
    {
        "address": "0xRecipientAddress2",
        "pubkey_hex": "04aa1122..."
    }
]

IPFS_API = "/ip4/127.0.0.1/tcp/5002/http"

# ---------------------------------------------------

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path, password):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    enc_data = salt + iv + encryptor.tag + ciphertext

    # ذخیره نسخه‌ی محلی (اختیاری)
    enc_path = file_path + ".enc"
    with open(enc_path, 'wb') as f:
        f.write(enc_data)

    # --- آپلود فایل رمز‌شده روی IPFS ---
    try:
        client = ipfshttpclient.connect(IPFS_API)
        cid = client.add_bytes(enc_data)
    except ipfshttpclient.exceptions.TimeoutError:
        messagebox.showerror("IPFS Timeout", "IPFS request timed out. Make sure the daemon is running.")
        return
    except Exception as e:
        messagebox.showerror("IPFS Error", f"Failed to upload to IPFS:\n{e}")
        return

    # --- رمزکردن کلید برای هر گیرنده ---
    enc_keys = []
    for r in RECIPIENTS:
        pubkey = r["pubkey_hex"]
        try:
            enc_key = ecies_encrypt(pubkey, key)
            enc_keys.append({
                "address": r["address"],
                "enc_key_hex": enc_key.hex()
            })
        except Exception as e:
            messagebox.showerror("ECIES Error", f"Error encrypting key for {r['address']}: {e}")
            return

    # --- ذخیره اطلاعات متادیتا ---
    record = {
        "original_file": os.path.basename(file_path),
        "cid": cid,
        "recipients": enc_keys,
        "salt_hex": salt.hex(),
        "iv_hex": iv.hex()
    }

    with open(file_path + "_record.json", "w") as f:
        json.dump(record, f, indent=2)

    messagebox.showinfo("Success", f"Encrypted & uploaded!\nCID: {cid}")

def decrypt_file(file_path, password):
    with open(file_path, 'rb') as f:
        data = f.read()
    
    salt, iv, tag, ciphertext = data[:16], data[16:28], data[28:44], data[44:]
    key = derive_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
    decryptor = cipher.decryptor()
    
    decrypted_data = decryptor.update(ciphertext) + decryptor.finalize()
    
    decrypted_file = file_path.replace(".enc", "")
    with open(decrypted_file, 'wb') as f:
        f.write(decrypted_data)
    
    messagebox.showinfo("Success", f"Decrypted: {decrypted_file}")

# ------------------ GUI ------------------

def select_files_encrypt():
    files = filedialog.askopenfilenames()
    password = password_entry.get()
    if files and password:
        for file in files:
            encrypt_file(file, password)
    else:
        messagebox.showerror("Error", "Select files and enter a password!")

def select_files_decrypt():
    files = filedialog.askopenfilenames()
    password = password_entry.get()
    if files and password:
        for file in files:
            decrypt_file(file, password)
    else:
        messagebox.showerror("Error", "Select files and enter a password!")

root = tk.Tk()
root.title("Blockchain Secure Encryptor")
root.geometry("400x250")

tk.Label(root, text="Enter Password:").pack()
password_entry = tk.Entry(root, show="*", width=30)
password_entry.pack()

encrypt_button = tk.Button(root, text="Encrypt + Upload to IPFS", command=select_files_encrypt)
encrypt_button.pack(pady=10)

decrypt_button = tk.Button(root, text="Decrypt Files", command=select_files_decrypt)
decrypt_button.pack(pady=10)

root.mainloop()
