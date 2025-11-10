from eth_keys import keys

def pubkey_from_private_key(private_key_hex: str) -> str:
    """
    Takes a hex private key (0x... یا فقط 64 hex chars)
    Returns the uncompressed public key (0x04-prefixed, 130 chars)
    """
    # حذف 0x اگر وجود داشت
    pk_hex = private_key_hex[2:] if private_key_hex.startswith("0x") else private_key_hex

    if len(pk_hex) != 64:
        raise ValueError("Private key must be 32 bytes (64 hex chars)")

    priv_key = keys.PrivateKey(bytes.fromhex(pk_hex))
    pub_key = priv_key.public_key
    return pub_key.to_hex()  # 0x04-prefixed, 130 chars

# --------------------------
# تست
if __name__ == "__main__":
    priv = input("Paste your private key (0x... or 64 hex chars): ").strip()
    try:
        pub = pubkey_from_private_key(priv)
        print("Public key:", pub)
    except Exception as e:
        print("Error:", e)
