# 🛡️ AegisVault — Zero-Knowledge Password Manager & CNS Security Suite

[![Live Demo](https://img.shields.io/badge/Live%20Demo-Vercel%20Production-00f2fe?style=for-the-badge&logo=vercel&logoColor=white)](https://crypto-aegis-vault.vercel.app)
[![Cryptography](https://img.shields.io/badge/Standard-AES--256--GCM%20AEAD-4facfe?style=for-the-badge&logo=shield)](https://csrc.nist.gov/publications/detail/sp/800-38d/final)
[![KDF](https://img.shields.io/badge/KDF-PBKDF2--HMAC--SHA256%20(600k%20iters)-7f00ff?style=for-the-badge)](https://tools.ietf.org/html/rfc8018)
[![License](https://img.shields.io/badge/License-MIT-blue.svg?style=for-the-badge)](LICENSE)

> An industrial-grade **Zero-Knowledge Password Manager** and **Cryptography & Network Security (CNS)** academic suite implementing **AES-256-GCM AEAD**, **PBKDF2-HMAC-SHA256 (600,000 rounds)**, interactive **Rijndael Galois Field $GF(2^8)$ visual cipher rounds**, and a real-time **Cryptographic Threat Simulator**.

🌐 **Production Deployment:** [https://crypto-aegis-vault.vercel.app](https://crypto-aegis-vault.vercel.app)

---

## 📑 Table of Contents
- [Architecture & Cryptographic Primitives](#-architecture--cryptographic-primitives)
- [Key Features](#-key-features)
- [Web Application Modules](#-web-application-modules)
- [Python CLI Suite (`vault_cli.py`)](#-python-cli-suite-vault_clipy)
- [Unit Testing & Cryptographic Verification (`test_vault.py`)](#-unit-testing--cryptographic-verification-test_vaultpy)
- [Directory Structure](#-directory-structure)
- [Local Development & Setup](#-local-development--setup)
- [Deployment](#-deployment)
- [Security Guarantees](#-security-guarantees)
- [Academic Context](#-academic-context)

---

## 🔒 Architecture & Cryptographic Primitives

AegisVault enforces a strict **Zero-Knowledge Architecture**: master passwords and unencrypted payloads are **never stored on disk or transmitted over any network**. All cryptographic transformations occur client-side in volatile memory using native hardware-accelerated APIs (**Web Cryptography API** in the browser, and the **hazmat primitives** of Python `cryptography` in the CLI).

| Parameter | Specification | Standard / Reference |
| :--- | :--- | :--- |
| **Symmetric Cipher** | `AES-256-GCM` (Galois/Counter Mode) | [NIST SP 800-38D](https://csrc.nist.gov/publications/detail/sp/800-38d/final) |
| **Cipher Key Size** | 256 bits (32 bytes) | FIPS 197 |
| **Key Derivation Function** | `PBKDF2-HMAC-SHA256` | [RFC 8018 (PKCS #5 v2.1)](https://tools.ietf.org/html/rfc8018) |
| **KDF Work Factor** | **600,000 Iterations** | [OWASP Password Storage Guidelines (2023+)](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) |
| **KDF Salt Size** | 256 bits (32 bytes) CSPRNG | Cryptographically secure pseudo-random generation |
| **Initialization Vector (Nonce)** | 96 bits (12 bytes) CSPRNG | Unique per encryption (ensures IND-CPA & IND-CCA2) |
| **Authentication Tag** | 128 bits (16 bytes) GHASH over $GF(2^{128})$ | Protects against bit-flipping & man-in-the-middle tampering |
| **Zero-Knowledge Auth Verifier** | `SHA-256(Master_Key)` | Verifies authorization without exposing the master password |
| **Key Lifecycle** | Volatile RAM only | Key purged on logout, lock, or 5-minute inactivity |

### Mathematical Key Derivation Flow
```
Master Password ──┐
                  ├──> [PBKDF2-HMAC-SHA256 (600,000 Iterations)] ──> Derived 256-bit Key
256-bit Salt   ──┘                                                              │
                                                                                ├──> SHA-256 ──> Auth Verifier (Zero-Knowledge)
                                                                                │
                                                                                └──> AES-256-GCM Encrypt/Decrypt
                                                                                          ▲
                                                                                          │
                                                                                     96-bit Nonce
```

---

## ✨ Key Features

- 🔐 **Zero-Knowledge Storage**: No unencrypted credential ever leaves browser memory.
- 🧪 **Interactive AES-256 Visualizer**: Step through all 14 rounds of AES in real-time. Watch the $4 \times 4$ State Matrix transform across **SubBytes**, **ShiftRows**, **MixColumns**, and **AddRoundKey**.
- 💥 **Threat & Attack Simulator**:
  - **Ciphertext Bit-Flipping Attack**: Proves how GCM's 128-bit GHASH authentication tag instantly halts corrupted packets before plaintext exposure.
  - **Nonce-Reuse Attack (GCM "Forbidden Attack")**: Demonstrates how reusing an IV destroys authenticity and allows GHASH key recovery.
  - **KDF Work-Factor Benchmark**: Explains how 600,000 iterations counter GPU hashcat clusters.
- 🎲 **Unbiased Password Generator**: Uses CSPRNG rejection sampling to eliminate modulo bias.
- 📊 **Real-time Shannon Entropy Analyzer**: Measures true information entropy in bits ($H = L \cdot \log_2 N$).
- 📦 **Dual Implementations**: Full-featured Web GUI and standalone Python CLI with 100% cryptographic parity.

---

## 🖥️ Web Application Modules

### 1. Password Vault
- Manage Credentials, Credit Cards, Secure Notes, and API Keys.
- Instant search and category filtering.
- In-memory auto-lock timer (default: 5 minutes of inactivity).
- Encrypted JSON export and import for seamless zero-knowledge backups.

### 2. Password Generator & Entropy Meter
- Configurable length (8–64 characters) with granular character set toggles (Uppercase, Lowercase, Digits, Symbols).
- Live calculation of **Shannon Entropy** in bits, crack-time estimations across multiple threat tiers (Consumer CPU, RTX 4090 GPU Rig, Distributed Botnet), and password strength scoring.

### 3. Security Audit
- Automatic detection of reused passwords.
- Flagging of low-entropy or vulnerable credentials (< 50 bits of entropy).
- Overall Vault Health Percentage.

### 4. AES-256 Lab & Visualizer
- Step-by-step state matrix visualizer for standard 128-bit block size.
- Exact Rijndael S-Box lookup table in Galois Field $GF(2^8)$.
- Interactive round selector (Rounds 1–14).

### 5. Threat Simulator
- Live interactive demonstrations of cryptographic vulnerabilities and defenses.
- Bit-tampering demonstration with custom byte-index manipulation.

### 6. CNS Theory & Viva Reference
- Academic notes covering:
  - Symmetric vs Asymmetric Ciphers
  - Block Cipher Modes (ECB, CBC, CTR, GCM)
  - Shannon's Confusion and Diffusion Principles
  - Birthday Paradox & Collision Resistance

---

## 🐍 Python CLI Suite (`vault_cli.py`)

AegisVault includes an enterprise-grade command-line tool implemented with Python's `cryptography` hazmat library that shares the exact cryptographic format with the web application.

### Installation

```bash
# Clone the repository
git clone https://github.com/<your-username>/crypto-aegis-vault.git
cd crypto-aegis-vault

# Install required dependencies
pip install cryptography
```

### CLI Commands

#### 1. Initialize a New Vault
```bash
python3 vault_cli.py --init
```
Prompts for a master password, derives the 256-bit key via 600,000 PBKDF2 rounds, creates a 256-bit salt, and initializes `vault_store.json`.

#### 2. Add a New Credential
```bash
python3 vault_cli.py add
```
Interactively prompts for title, username, password, category, and notes.

#### 3. List All Stored Credentials
```bash
python3 vault_cli.py list
```
Displays an encrypted vault summary table after verifying the master password.

#### 4. Retrieve and Decrypt a Specific Credential
```bash
python3 vault_cli.py get --id item-1
```

#### 5. Run a Cryptographic Security Audit
```bash
python3 vault_cli.py audit
```
Evaluates all entries for Shannon entropy weaknesses and flagged password reuse.

#### 6. Generate a Cryptographically Unbiased Password
```bash
python3 vault_cli.py generate --length 24
```

#### 7. Execute the Bit-Flipping Attack Demo
```bash
python3 vault_cli.py test-attack
```
Simulates an in-transit bit flip on an AES-256-GCM ciphertext, proving that the GHASH tag rejects the packet before decryption.

---

## 🧪 Unit Testing & Cryptographic Verification (`test_vault.py`)

Comprehensive unit tests verify NIST standard compliance, tamper-resistance, and mathematical invariants.

### Run Tests

```bash
python3 -m unittest test_vault.py -v
```

### Test Coverage
- **PBKDF2 Determinism & Salt Separation**: Confirms identical inputs yield identical keys, and different salts yield completely divergent keys.
- **AES-256-GCM Roundtrip**: Validates authenticated encryption and decryption.
- **Bit-Flipping Tamper Detection**: Flips bit 0 of the ciphertext and verifies that `InvalidTag` is raised every time.
- **Nonce Uniqueness (Semantic Security / IND-CPA)**: Confirms encrypting identical plaintext multiple times produces distinct ciphertexts.
- **Shannon Entropy Sanity Checks**: Validates entropy calculations against known mathematical baselines.
- **Vault Persistence**: Tests initialization, loading, mutation, and recovery.

---

## 📂 Directory Structure

```plaintext
CRYPTO/
├── index.html            # Main Single-Page Web Application UI
├── style.css             # Cyberpunk Matrix Design System & Layout
├── app.js                # UI State Controller, Event Handlers & Auto-Lock
├── crypto-core.js        # Web Cryptography API Core (AES-GCM, PBKDF2, CSPRNG)
├── aes-visualizer.js     # AES-256 14-Round State Matrix Visualizer in GF(2^8)
├── attack-simulator.js   # Interactive Bit-Flipping & Nonce Threat Demos
├── vault_cli.py          # Standalone Python CLI Vault Implementation
├── test_vault.py         # Unit Tests & Formal Cryptographic Test Vectors
├── assets/               # Visual Assets (Banners, Icons)
├── .vercelignore         # Deployment Exclusions for Vercel
└── README.md             # Project Documentation & Architecture Guide
```

---

## 💻 Local Development & Setup

### Running the Web Application Locally

Because AegisVault utilizes modern Web Cryptography APIs and ES modules, run it via any local HTTP server:

```bash
# Using Python built-in server
python3 -m http.server 8000

# Open in your browser
open http://localhost:8000
```

Alternatively, use Node's `serve`:
```bash
npx serve .
```

---

## 🚀 Deployment

The web suite is configured for instant zero-configuration deployment on **Vercel**, **Netlify**, or **GitHub Pages**.

### Deploy to Vercel

```bash
# Install Vercel CLI & deploy to production
npx vercel --prod
```

---

## 🛡️ Security Guarantees

1. **Zero-Knowledge**: Neither passwords, keys, nor unencrypted credentials ever leave the client machine.
2. **Timing-Attack Resilience**: Auth verification utilizes constant-time hash comparisons.
3. **Memory Safety**: Ephemeral master keys reside exclusively in volatile memory; page reload or auto-lock instantly flushes them from RAM.
4. **No Modulo Bias**: Password generation uses rejection sampling over CSPRNG buffers rather than naive modulo operators ($R \pmod N$).
5. **Authenticated Encryption (AEAD)**: Uses Galois/Counter Mode to guarantee both **Confidentiality** and **Integrity/Authenticity**.

---

## 🎓 Academic Context

- **Course**: Cryptography & Network Security (CNS)
- **Key Concepts Covered**:
  - Symmetric Key Cryptography (AES, FIPS 197)
  - Key Derivation Functions (KDFs) & Brute-Force Hardening
  - Finite Fields / Galois Fields ($GF(2^8)$ and $GF(2^{128})$)
  - Authenticated Encryption with Associated Data (AEAD)
  - Information Entropy (Claude Shannon, 1948)
  - Known Attacks (Bit-Flipping, Replay, Nonce Collision, Dictionary/Rainbow Table)

---

## 📄 License

This project is licensed under the **MIT License** — feel free to use it for academic, research, or personal projects.

