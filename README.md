# Secure File Manager

A secure and private file storage system leveraging **IPFS** and **Ethereum (Sepolia)**. Users can upload confidential files, encrypt them with AES, and securely grant access to other users via blockchain-controlled permissions.

---

## Table of Contents

1. Features
2. Prerequisites
3. Installation
4. Configuration
5. Deploying the Smart Contract
6. Running an IPFS Node
7. Uploading Files (Owner)
8. Adding/Managing Recipients
9. Decrypting Files (Recipient)
10. Recovering Original File
11. Project Structure
12. Notes

---

## Features

* AES-256 encryption for uploaded files.
* Upload encrypted files to **IPFS** and store the CID.
* Manage recipient access via Ethereum smart contract.
* Support adding or revoking access at any time.
* Local JSON record for each upload, containing metadata and encrypted AES keys.
* Safe and private; AES keys never exposed publicly.

---

## Prerequisites

* Python 3.12+
* Node.js (optional for js-ipfs)
* IPFS daemon (local node recommended)
* Ethereum wallet and Sepolia testnet account

---

## Installation

1. Clone the repository:

```bash
git clone https://github.com/soheilxcrypto/Vaulty.git
cd Vaulty
```

2. Install Python dependencies:

```bash
pip install -r requirements.txt
```

If `requirements.txt` is not present:

```bash
pip install web3 eth-account eth-keys cryptography ecies requests
```

---

## Configuration

1. Edit `config.json`:

```json
{
  "eth_rpc": "https://sepolia.infura.io/v3/YOUR_INFURA_PROJECT_ID",
  "contract_address": "0xYourDeployedContractAddress",
  "owner_private_key": "0xYourOwnerPrivateKey",
  "ipfs_api_url": "http://127.0.0.1:5002/api/v0/add",
  "recipients": [
    {
      "address": "0x7De8BEFf92a498Ddf28C8ACE0eD0298aD61Ee5B5",
      "pubkey_hex": "04f8e3b..."
    },
    {
      "address": "0xdFF1824bE88e9b916869Fc05D2156F54be2a5b35",
      "pubkey_hex": "048e9ac..."
    }
  ]
}
```

* `owner_private_key`: Owner wallet for uploading files.
* `recipients`: List of addresses and their public keys.
* You can generate a public key from a private key using `converter/pubkey-generator`.

---

## Deploying the Smart Contract

1. Use `FileRegistry.sol` for Sepolia testnet deployment.
2. After deployment, copy the contract address into `config.json`.
3. Ensure ABI matches the `CONTRACT_ABI` in `uploader.py`.

---

## Running an IPFS Node

```bash
ipfs daemon --api /ip4/127.0.0.1/tcp/5002
```

* The project uploads encrypted files to your local IPFS node.
* Ensure the API endpoint matches `config.json`.

---

## Uploading Files (Owner)

1. Run uploader:

```bash
python uploader.py path/to/your/file.png
```

2. Output:

* Encrypted file: `/encrypt-uploads/ences/<filename>.enc`
* JSON record: `/encrypt-uploads/jsons/<filename>_upload_record.json`
* Transaction hash printed to terminal
* IPFS CID

3. The uploader script will:

* Generate AES key
* Encrypt file
* Upload to IPFS
* Wrap AES key per recipient
* Send `addFile` transaction to smart contract
* Save local JSON record

---

## Adding/Managing Recipients

* Add a recipient after upload:

```python
# Use smart contract function assignKey
contract.functions.assignKey(fileId, recipient_address, enc_key_bytes)
```

* Revoke a recipient:

```python
contract.functions.revokeKey(fileId, recipient_address)
```

* `enc_key_bytes` can be generated with `converter/pubkey-generator` using the recipient's private key to compute the public key.

---

## Decrypting Files (Recipient)

1. Use `recipien-decrypt.py`:

```bash
python recipien-decrypt.py encrypt-uploads/jsons/<filename>_upload_record.json 0xRecipientPrivateKey
```

2. Output:

* Decrypted binary: `recovered_from_ipfs.bin` (or custom path)
* The script will:

  * Read JSON record
  * Find recipient AES key
  * Fetch encrypted file from IPFS
  * Decrypt using AESGCM

---

## Recovering Original File

After decryption:

```bash
mv recovered_from_ipfs.bin original_filename.ext
```

* Rename to original extension (png, pdf, txt, etc.)
* Open normally with corresponding program.

---

## Project Structure

```
secure-file-manager/
├── uploader.py
├── recipien-decrypt.py
├── converter/
│   └── pubkey-generator.py
├── encrypt-uploads/
│   ├── ences/
│   └── jsons/
├── FileRegistry.sol
├── config.json
├── README.md
```

---

## Notes

* AES keys are sensitive! Never share `aes_key_hex`.
* Keep your private keys safe; losing them means losing access.
* Test on **Sepolia testnet** first before moving to mainnet.
* Ensure IPFS node is running during upload and decryption.

---

## License

MIT License
