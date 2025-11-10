from eth_keys import keys
import os

priv_bytes = os.urandom(32)  # حتماً 32 بایت
priv = keys.PrivateKey(priv_bytes)
pub_hex = priv.public_key.to_hex()
print("Private key:", priv.to_hex())
print("Public key:", pub_hex)
