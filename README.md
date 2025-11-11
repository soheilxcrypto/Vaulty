# Secure File Manager

A secure and private file storage system leveraging **IPFS** and **Ethereum (Sepolia)**.  
Users can upload confidential files, encrypt them with AES, and securely grant access to other users via blockchain-controlled permissions.

---

## Table of Contents
1. [Features](#features)
2. [Prerequisites](#prerequisites)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Deploying the Smart Contract](#deploying-the-smart-contract)
6. [Running an IPFS Node](#running-an-ipfs-node)
7. [Uploading Files (Owner)](#uploading-files-owner)
8. [Adding/Managing Recipients](#addingmanaging-recipients)
9. [Decrypting Files (Recipient)](#decrypting-files-recipient)
10. [Recovering Original File](#recovering-original-file)
11. [Project Structure](#project-structure)
12. [Notes](#notes)

---

## Features

- AES-256 encryption for uploaded files.
- Upload encrypted files to **IPFS** and store the CID.
- Manage recipient access via Ethereum smart contract.
- Support adding or revoking access at any time.
- Local JSON record for each upload, containing metadata and encrypted AES keys.
- Safe and private; AES keys never exposed publicly.

---

## Prerequisites

- **Python 3.12+**
- **Node.js** (optional if you want to run IPFS locally via js-ipfs)
- **IPFS daemon** (local node recommended)
- Ethereum wallet and Sepolia testnet account

---

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/secure-file-manager.git
cd secure-file-manager
