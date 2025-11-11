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

def normalize_priv_hex(priv_hex):
    # ensure 0x prefix for libraries that expect it
    if priv_hex.startswith("0x") or priv_hex.startswith("0X"):
        return priv_hex
    return "0x" + priv_hex

def find_enc_hex_for_priv(rec, recipient_priv_hex):
    """
    Find the recipient entry in rec['recipients'] that matches the address
    derived from recipient_priv_hex. If not found, raise an error.
    """
    w3 = Web3()
    priv_norm = normalize_priv_hex(recipient_priv_hex)
    try:
        acct = w3.eth.account.from_key(priv_norm)
    except Exception as e:
        raise RuntimeError(f"failed to derive address from private key: {e}")

    derived_addr = acct.address.lower()

    # search recipients for matching address (case-insensitive)
    for r in rec.get("recipients", []):
        addr = r.get("address", "")
        if addr and addr.lower() == derived_addr:
            enc_hex = r.get("enc_key_hex")
            if not enc_hex:
                raise RuntimeError("matching recipient entry found but no enc_key_hex present")
            return enc_hex

    # if we reach here, no exact match found
    raise RuntimeError(f"recipient address {acct.address} not found in record recipients")

def decrypt_flow(record_path, recipient_priv_hex, out_path="recovered.bin"):
    rec = None
    with open(record_path, "r", encoding="utf8") as f:
        rec = json.load(f)
    cid = rec["cid"]

    # find enc_key for this recipient (match by derived address)
    try:
        enc_hex = find_enc_hex_for_priv(rec, recipient_priv_hex)
    except Exception as e:
        # keep error explicit and don't silently fallback to wrong recipient
        raise

    # normalize hex (allow "0x..." or raw hex)
    if enc_hex.startswith("0x") or enc_hex.startswith("0X"):
        enc_hex_body = enc_hex[2:]
    else:
        enc_hex_body = enc_hex

    try:
        enc_bytes = bytes.fromhex(enc_hex_body)
    except Exception as e:
        raise RuntimeError(f"failed to decode enc_key_hex from hex: {e}")

    # 1) recover AES key using ECIES decrypt (ecies expects priv hex '0x..')
    priv_for_ecies = normalize_priv_hex(recipient_priv_hex)
    try:
        aes_key = ecies_decrypt(priv_for_ecies, enc_bytes)  # returns bytes
    except ValueError as e:
        # MAC check failed or wrong key -> clearer message
        raise RuntimeError(f"ECIES decrypt failed (possible wrong private key or corrupted enc_key): {e}")
    except Exception as e:
        raise RuntimeError(f"ECIES decrypt unexpected error: {e}")

    # 2) download payload from IPFS (assuming local ipfs on 5002)
    ipfs_cat_url = "http://127.0.0.1:5002/api/v0/cat"
    try:
        r = requests.post(ipfs_cat_url, params={"arg": cid}, timeout=120)
        r.raise_for_status()
    except Exception as e:
        raise RuntimeError(f"failed to fetch from IPFS ({ipfs_cat_url} arg={cid}): {e}")

    payload = r.content
    if len(payload) < 13:
        raise RuntimeError("payload too short to contain iv + ct + tag")

    # payload was iv(12) + ct+tag
    iv = payload[:12]
    ct_tag = payload[12:]
    aesgcm = AESGCM(aes_key)
    try:
        plaintext = aesgcm.decrypt(iv, ct_tag, None)
    except Exception as e:
        raise RuntimeError(f"AES-GCM decrypt failed (wrong key/iv/ciphertext): {e}")

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
