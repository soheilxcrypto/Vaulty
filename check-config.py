import json, sys, os
from eth_keys import keys
from web3 import Web3

def load(path="config.json"):
    with open(path,'r',encoding='utf8') as f:
        return json.load(f)

def check_privkey(pk):
    if not isinstance(pk,str) or not pk.startswith("0x") or len(pk[2:])!=64:
        return False
    return True

def check_pubkey(pub):
    p = pub[2:] if pub.startswith("0x") else pub
    return len(p)==130 and p.startswith("04")

def main(path="config.json"):
    if not os.path.exists(path):
        print("❌ config.json not found")
        return 1
    cfg = load(path)
    ok = True
    if "eth_rpc" not in cfg or not cfg["eth_rpc"]:
        print("⚠️ eth_rpc empty. You'll need an RPC URL.")
    if "contract_address" not in cfg or not Web3.is_address(cfg["contract_address"]):
        print("❌ contract_address missing or invalid")
        ok = False
    if "owner_private_key" not in cfg or not check_privkey(cfg["owner_private_key"]):
        print("❌ owner_private_key missing or wrong length (must be 0x + 64 hex chars)")
        ok = False
    if "ipfs_api_url" in cfg:
        print("IPFS API URL:", cfg["ipfs_api_url"])
    else:
        print("⚠️ ipfs_api_url not set; defaulting may fail")
    recs = cfg.get("recipients", [])
    if not recs:
        print("⚠️ recipients list is empty")
    for r in recs:
        a = r.get("address")
        p = r.get("pubkey_hex")
        if not a or not Web3.is_address(a):
            print("❌ Recipient has invalid address:", a)
            ok=False
        if not p or not check_pubkey(p):
            print("❌ Recipient pubkey invalid (must be uncompressed 0x04... 130 hex chars) for", a)
            ok=False
    if ok:
        print("✅ config.json looks OK")
        return 0
    else:
        print("Fix the issues above and re-run.")
        return 2

if __name__ == "__main__":
    sys.exit(main(sys.argv[1] if len(sys.argv)>1 else "config.json"))
