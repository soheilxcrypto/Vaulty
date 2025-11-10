#!/usr/bin/env python3
import os
import json
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from ecies import encrypt as ecies_encrypt
import requests
import threading
from eth_keys import keys
import binascii

# ------------------ پیکربندی ------------------
RECIPIENTS_PATH = "recipients.json"  # فایل ذخیره recips
IPFS_API_URL = "http://127.0.0.1:5002/api/v0/add"
# ------------------------------------------------

# بارگذاری recipients از فایل (اگر وجود داشته باشه)
def load_recipients():
    if os.path.exists(RECIPIENTS_PATH):
        with open(RECIPIENTS_PATH, "r", encoding="utf8") as f:
            try:
                arr = json.load(f)
                # normalize: remove 0x prefix from pubkeys
                for r in arr:
                    if 'pubkey_hex' in r:
                        p = r['pubkey_hex']
                        if p.startswith("0x"):
                            r['pubkey_hex'] = p[2:]
                return arr
            except Exception:
                return []
    return []

def save_recipients(arr):
    with open(RECIPIENTS_PATH, "w", encoding="utf8") as f:
        json.dump(arr, f, indent=2, ensure_ascii=False)

RECIPIENTS = load_recipients()

# ------------------ ابزارهای کلید ------------------

def generate_test_keypair():
    """تولید private/public تستی (برای توسعه)"""
    priv_bytes = os.urandom(32)
    priv = keys.PrivateKey(priv_bytes)
    pub_hex = priv.public_key.to_hex()  # '0x04....'
    return priv.to_hex(), pub_hex  # هر دو شامل 0x prefix

def pubkey_from_private_hex(priv_hex):
    """اگر user یک private key بهت داد، این تابع pubkey استخراج می‌کنه."""
    # قبول می‌کنیم priv_hex با/بدون 0x باشه
    if priv_hex.startswith("0x"):
        priv_hex = priv_hex[2:]
    if len(priv_hex) != 64:
        raise ValueError("Private key must be 32 bytes / 64 hex chars.")
    try:
        priv = keys.PrivateKey(bytes.fromhex(priv_hex))
    except Exception as e:
        raise ValueError(f"Invalid private key: {e}")
    return priv.public_key.to_hex()  # به صورت 0x04...

def validate_pubkey_hex(pub_hex):
    """اعتبارسنجی ساده: باید uncompressed و با '04' شروع و طول 130 hex (بدون 0x) باشه."""
    if pub_hex.startswith("0x"):
        pub_hex = pub_hex[2:]
    if len(pub_hex) != 130:
        raise ValueError("Public key must be uncompressed 65 bytes (130 hex chars, prefixed 04).")
    if not pub_hex.startswith("04"):
        raise ValueError("Public key must be uncompressed (start with '04').")
    # also ensure hex chars
    try:
        bytes.fromhex(pub_hex)
    except Exception:
        raise ValueError("Public key contains non-hex characters.")
    return pub_hex

# ------------------ رمزنگاری و IPFS ------------------

def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def upload_to_ipfs(data: bytes):
    try:
        files = {"file": ("file.enc", data)}
        response = requests.post(IPFS_API_URL, files=files, timeout=300)  # 5 min
        response.raise_for_status()
        # Kubo responds with lines of JSON when chunked; but /add returns JSON with Hash
        # requests will parse the final JSON; if not, fallback
        j = response.json()
        if "Hash" in j:
            return j["Hash"]
        # fallback attempt: parse text
        text = response.text.strip().splitlines()[-1]
        try:
            import json as _j
            parsed = _j.loads(text)
            return parsed.get("Hash")
        except Exception:
            raise Exception("Unexpected IPFS response: " + response.text)
    except requests.exceptions.Timeout:
        raise Exception("IPFS request timed out. Make sure the daemon is running.")
    except Exception as e:
        raise Exception(f"Failed to upload to IPFS: {e}")

def encrypt_file(file_path, password):
    try:
        salt = os.urandom(16)
        key = derive_key(password, salt)
        iv = os.urandom(12)
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        # خواندن فایل کامل (اگه فایل خیلی بزرگه بعدا chunk می‌کنیم)
        with open(file_path, 'rb') as f:
            plaintext = f.read()

        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        enc_data = salt + iv + encryptor.tag + ciphertext

        # ذخیره محلی
        enc_path = file_path + ".enc"
        with open(enc_path, 'wb') as f:
            f.write(enc_data)

        # آپلود
        try:
            cid = upload_to_ipfs(enc_data)
        except Exception as e:
            messagebox.showerror("IPFS Error", str(e))
            return

        # wrap key برای recipients
        enc_keys = []
        for r in RECIPIENTS:
            pubkey = r.get("pubkey_hex")
            if not pubkey:
                messagebox.showerror("ECIES Error", f"No pubkey for {r.get('address')}")
                return
            # normalize
            if pubkey.startswith("0x"):
                pubkey = pubkey[2:]
            # validate length parity
            if len(pubkey) % 2 != 0:
                messagebox.showerror("ECIES Error", f"Invalid pubkey length for {r.get('address')}")
                return
            try:
                enc_key = ecies_encrypt(pubkey, key)
                enc_keys.append({"address": r["address"], "enc_key_hex": enc_key.hex()})
            except Exception as e:
                messagebox.showerror("ECIES Error", f"Error encrypting key for {r.get('address')}: {e}")
                return

        # ذخیره رکورد محلی
        record = {
            "original_file": os.path.basename(file_path),
            "cid": cid,
            "recipients": enc_keys,
            "salt_hex": salt.hex(),
            "iv_hex": iv.hex()
        }
        with open(file_path + "_record.json", "w", encoding="utf8") as f:
            json.dump(record, f, indent=2, ensure_ascii=False)

        messagebox.showinfo("Success", f"Encrypted & uploaded!\nCID: {cid}")

    except Exception as ex:
        messagebox.showerror("Encryption Error", str(ex))

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

# ------------------ GUI: مدیریت Recipients ------------------

def refresh_recipient_listbox():
    recipient_listbox.delete(0, tk.END)
    for r in RECIPIENTS:
        addr = r.get("address", "<no address>")
        pk = r.get("pubkey_hex", "")[:8] + ("..." if len(r.get("pubkey_hex",""))>8 else "")
        recipient_listbox.insert(tk.END, f"{addr}  |  {pk}")

def add_recipient_manual():
    addr = simpledialog.askstring("Add Recipient", "Enter recipient address (0x...):", parent=root)
    if not addr:
        return
    pub = simpledialog.askstring("Add Recipient", "Enter recipient public key (uncompressed hex, 0x04... or 04...):", parent=root)
    if not pub:
        return
    try:
        valid = validate_pubkey_hex(pub)
    except Exception as e:
        messagebox.showerror("Invalid pubkey", str(e))
        return
    RECIPIENTS.append({"address": addr, "pubkey_hex": valid})
    save_recipients(RECIPIENTS)
    refresh_recipient_listbox()
    messagebox.showinfo("Added", f"Recipient {addr} added.")

def generate_and_add_keypair():
    priv_hex, pub_hex = generate_test_keypair()
    # strip 0x for storage
    RECIPIENTS.append({"address": "test-"+priv_hex[:8], "pubkey_hex": pub_hex[2:]})
    save_recipients(RECIPIENTS)
    refresh_recipient_listbox()
    # show the keypair to user (must be kept secret)
    messagebox.showinfo("Generated keypair (keep private key secret)",
                        f"Private (hex): {priv_hex}\n\nPublic (hex): {pub_hex}\n\nPublic saved to recipients.json")

def add_from_private_key():
    priv = simpledialog.askstring("Import private key", "Paste private key hex (0x... or 64 hex chars):", parent=root)
    if not priv:
        return
    try:
        pub = pubkey_from_private_hex(priv)  # returns 0x04...
    except Exception as e:
        messagebox.showerror("Invalid private key", str(e))
        return
    addr = simpledialog.askstring("Enter recipient address to associate", "Enter recipient address (0x...):", parent=root)
    if not addr:
        return
    RECIPIENTS.append({"address": addr, "pubkey_hex": pub[2:]})
    print (RECIPIENTS)
    save_recipients(RECIPIENTS)
    refresh_recipient_listbox()
    messagebox.showinfo("Imported", "Public key extracted and recipient saved.")

def remove_selected_recipient():
    sel = recipient_listbox.curselection()
    if not sel:
        return
    idx = sel[0]
    r = RECIPIENTS.pop(idx)
    save_recipients(RECIPIENTS)
    refresh_recipient_listbox()
    messagebox.showinfo("Removed", f"Removed {r.get('address')}")

# ------------------ GUI: Encrypt/Decrypt ------------------

def run_encrypt_thread(file_path, password):
    threading.Thread(target=encrypt_file, args=(file_path, password), daemon=True).start()

def select_files_encrypt():
    files = filedialog.askopenfilenames()
    password = password_entry.get()
    if files and password:
        for file in files:
            run_encrypt_thread(file, password)
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

# ------------------ UI layout ------------------

root = tk.Tk()
root.title("Blockchain Secure Encryptor")
root.geometry("600x420")

tk.Label(root, text="Enter Password:").pack(anchor="w", padx=10, pady=(10,0))
password_entry = tk.Entry(root, show="*", width=40)
password_entry.pack(anchor="w", padx=10)

frame = tk.Frame(root)
frame.pack(fill="x", padx=10, pady=10)

encrypt_button = tk.Button(frame, text="Encrypt + Upload to IPFS", command=select_files_encrypt, width=25)
encrypt_button.grid(row=0, column=0, padx=5, pady=5)

decrypt_button = tk.Button(frame, text="Decrypt Files", command=select_files_decrypt, width=25)
decrypt_button.grid(row=0, column=1, padx=5, pady=5)

# Recipient manager UI
tk.Label(root, text="Recipients (address | pubkey prefix):").pack(anchor="w", padx=10)
recipient_listbox = tk.Listbox(root, height=8, width=80)
recipient_listbox.pack(padx=10, pady=(4,6))

btn_frame = tk.Frame(root)
btn_frame.pack(padx=10, pady=6)
tk.Button(btn_frame, text="Add (address+pubkey)", command=add_recipient_manual).grid(row=0, column=0, padx=4)
tk.Button(btn_frame, text="Import from private key", command=add_from_private_key).grid(row=0, column=1, padx=4)
tk.Button(btn_frame, text="Generate test keypair", command=generate_and_add_keypair).grid(row=0, column=2, padx=4)
tk.Button(btn_frame, text="Remove selected", command=remove_selected_recipient).grid(row=0, column=3, padx=4)

refresh_recipient_listbox()
root.mainloop()
