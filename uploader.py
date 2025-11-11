#!/usr/bin/env python3
import os, json, sys
import requests
from web3 import Web3
from eth_account import Account
from eth_keys import keys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import secrets
from ecies import encrypt as ecies_encrypt

# ----- تنظیمات -----
CONFIG_PATH = "config.json"
CONTRACT_ABI = [
    {
        "inputs": [
            {"internalType":"string","name":"cid","type":"string"},
            {"internalType":"address[]","name":"recipients","type":"address[]"},
            {"internalType":"bytes[]","name":"encKeys","type":"bytes[]"}
        ],
        "name":"addFile",
        "outputs":[{"internalType":"uint256","name":"","type":"uint256"}],
        "stateMutability":"nonpayable",
        "type":"function"
    }
]
# --------------------

def load_config(path=CONFIG_PATH):
    with open(path, "r", encoding="utf8") as f:
        return json.load(f)

def generate_aes_key():
    return secrets.token_bytes(32)  # 256-bit

def aes_encrypt_file(file_path, aes_key):
    # WARNING: Reads whole file into memory. For very large files implement chunked streaming.
    with open(file_path, "rb") as f:
        data = f.read()
    aesgcm = AESGCM(aes_key)
    iv = secrets.token_bytes(12)
    ct = aesgcm.encrypt(iv, data, None)  # returns ciphertext || tag (AESGCM lib appends tag)
    # We'll store: saltless design (key random) => file payload = iv || ct
    payload = iv + ct
    return payload, iv

def upload_to_ipfs_bytes(ipfs_api_url, payload_bytes, filename="file.enc"):
    files = {"file": (filename, payload_bytes)}
    resp = requests.post(ipfs_api_url, files=files, timeout=300)
    resp.raise_for_status()
    # resp.json() sometimes returns lines; parse last JSON line if multiple
    try:
        js = resp.json()
        if "Hash" in js:
            return js["Hash"]
    except Exception:
        text = resp.text.strip().splitlines()[-1]
        try:
            j = json.loads(text)
            return j.get("Hash")
        except Exception as e:
            raise RuntimeError("Unexpected IPFS response: " + resp.text)
    raise RuntimeError("No Hash in IPFS response")

def wrap_aes_key_for_recipients(aes_key, recipients):
    enc_list = []
    addresses = []
    for r in recipients:
        addr = Web3.to_checksum_address(r["address"])
        pub = r["pubkey_hex"]
        if pub.startswith("0x"):
            pub = pub[2:]
        # ecies expects hex pubkey uncompressed (04...)
        if len(pub) % 2 != 0:
            raise ValueError("pubkey hex odd length for " + addr)
        enc = ecies_encrypt(pub, aes_key)  # bytes
        enc_list.append(enc)
        addresses.append(addr)
    return addresses, enc_list

def send_addfile_tx(cfg, cid, recipient_addresses, enc_keys_bytes):
    w3 = Web3(Web3.HTTPProvider(cfg["eth_rpc"]))
    acct = Account.from_key(cfg["owner_private_key"])
    contract = w3.eth.contract(address=Web3.to_checksum_address(cfg["contract_address"]), abi=CONTRACT_ABI)

    enc_keys_hex = [Web3.to_hex(e) for e in enc_keys_bytes]

    nonce = w3.eth.get_transaction_count(acct.address)
    gas_estimate = contract.functions.addFile(cid, recipient_addresses, enc_keys_hex).estimate_gas({
        "from": acct.address
    })
    tx = contract.functions.addFile(cid, recipient_addresses, enc_keys_hex).build_transaction({
        "from": acct.address,
        "nonce": nonce,
        "gas": int(gas_estimate * 1.2),  # 20٪ حاشیه امنیت
        "gasPrice": w3.eth.gas_price
    })
    signed = acct.sign_transaction(tx)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)

    print("Transaction sent. Waiting for confirmation...")
    try:
        # صبر برای تأیید تراکنش
        receipt = w3.eth.wait_for_transaction_receipt(tx_hash, timeout=180, poll_latency=5)
    except Exception as e:
        raise RuntimeError(f"Transaction not confirmed or failed to fetch receipt: {e}")

    # بررسی وضعیت
    if receipt is None:
        raise RuntimeError("No transaction receipt returned by network.")
    if receipt.get("status") != 1:
        raise RuntimeError(f"Transaction failed. Receipt: {receipt}")

    print("✅ Transaction confirmed successfully!")
    print("📜 Block number:", receipt["blockNumber"])
    print("🔗 Tx hash:", tx_hash.hex())

    return tx_hash.hex()


def main():
    if len(sys.argv) < 2:
        print("Usage: python uploader.py <file-to-upload>")
        sys.exit(1)
    filepath = sys.argv[1]
    cfg = load_config(CONFIG_PATH)

    # 1) generate AES key (random)
    aes_key = generate_aes_key()
    print("Generated AES key (hex):", aes_key.hex())

    # 2) encrypt file
    payload, iv = aes_encrypt_file(filepath, aes_key)
    # مسیرهای خروجی
    base_dir = "encrypt-uploads"
    enc_dir = os.path.join(base_dir, "ences")
    json_dir = os.path.join(base_dir, "jsons")
    os.makedirs(enc_dir, exist_ok=True)
    os.makedirs(json_dir, exist_ok=True)

    enc_filename = os.path.basename(filepath) + ".enc"
    enc_path = os.path.join(enc_dir, enc_filename)
    with open(enc_path, "wb") as f:
        f.write(payload)
    print("Encrypted file saved:", enc_path)

    # 3) upload to IPFS
    cid = upload_to_ipfs_bytes(cfg["ipfs_api_url"], payload, enc_filename)
    print("Uploaded to IPFS CID:", cid)

    # 4) wrap AES key for recipients
    recipients = cfg["recipients"]
    recipient_addresses, enc_keys = wrap_aes_key_for_recipients(aes_key, recipients)
    print("Wrapped AES key for recipients:", recipient_addresses)

    # 5) call contract addFile
    txhash = send_addfile_tx(cfg, cid, recipient_addresses, enc_keys)
    print("addFile tx sent:", txhash)

    # 6) save local record (safe: contains aes_key! keep private)
    out = {
        "original_file": os.path.basename(filepath),
        "cid": cid,
        "iv_hex": iv.hex(),
        "aes_key_hex": aes_key.hex(),
        "recipients": [
            {"address": recipient_addresses[i], "enc_key_hex": enc_keys[i].hex()}
            for i in range(len(recipient_addresses))
        ]
    }
    out_filename = os.path.basename(filepath) + "_upload_record.json"
    outpath = os.path.join(json_dir, out_filename)
    with open(outpath, "w", encoding="utf8") as f:
        json.dump(out, f, indent=2, ensure_ascii=False)
    print("Saved local record:", outpath)
    print("Done. Keep aes_key_hex secret!")

if __name__ == "__main__":
    main()
