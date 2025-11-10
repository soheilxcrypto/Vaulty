#!/usr/bin/env python3
import sys, requests, json
from ecies import decrypt as ecies_decrypt
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from web3 import Web3

def load_record_or_contract(cfg_path, file_record_path=None, contract_address=None, fileId=None, recipient_address=None):
    # simple: use local upload_record.json (or fetch encKey from contract if desired)
    with open(file_record_path, "r", encoding="utf8") as f:
        rec = json.load(f)
    return rec

def decrypt_flow(record_path, recipient_priv_hex, out_path="recovered.bin"):
    rec = None
    with open(record_path, "r", encoding="utf8") as f:
        rec = json.load(f)
    cid = rec["cid"]
    # find enc_key for this recipient
    enc_hex = None
    # if recipient_priv_hex corresponds to known address, match by address; else, try first
    for r in rec["recipients"]:
        enc_hex = r["enc_key_hex"]
        break
    if not enc_hex:
        raise RuntimeError("no enc_key in record")

    enc_bytes = bytes.fromhex(enc_hex) if not enc_hex.startswith("0x") else bytes.fromhex(enc_hex[2:])
    # 1) recover AES key using ECIES decrypt (eciespy expects priv hex '0x..')
    aes_key = ecies_decrypt(recipient_priv_hex, enc_bytes)  # returns bytes

    # 2) download payload from IPFS (assuming local ipfs on 5002)
    ipfs_cat_url = "http://127.0.0.1:5002/api/v0/cat"
    r = requests.post(ipfs_cat_url, params={"arg": cid}, timeout=120)
    r.raise_for_status()
    payload = r.content
    # payload was iv(12) + ct+tag
    iv = payload[:12]
    ct_tag = payload[12:]
    aesgcm = AESGCM(aes_key)
    plaintext = aesgcm.decrypt(iv, ct_tag, None)
    with open(out_path, "wb") as f:
        f.write(plaintext)
    print("Decrypted saved to:", out_path)

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python recipient_decrypt.py <upload_record.json> <recipient_private_key_hex>")
        sys.exit(1)
    record_path = sys.argv[1]
    priv = sys.argv[2]
    decrypt_flow(record_path, priv, out_path="recovered_from_ipfs.bin")
