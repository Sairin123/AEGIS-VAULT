#!/usr/bin/env python3
"""
==============================================================================
AEGIS-VAULT : CLI CRYPTOGRAPHIC PASSWORD MANAGER (PYTHON EDITION)
==============================================================================
Course / Topic : Cryptography and Network Security (CNS)
Standard       : AES-256-GCM (NIST SP 800-38D) & PBKDF2-HMAC-SHA256 (RFC 8018)
Library        : Python `cryptography` hazardous materials primitives
==============================================================================
"""

import os
import sys
import json
import base64
import getpass
import secrets
import argparse
import math
from datetime import datetime
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

DEFAULT_VAULT_FILE = "vault_store.json"
PBKDF2_ITERATIONS = 600000
SALT_SIZE = 32   # 256 bits
NONCE_SIZE = 12  # 96 bits for AES-GCM

class AegisVaultCLI:
    def __init__(self, vault_path=DEFAULT_VAULT_FILE):
        self.vault_path = vault_path

    def derive_key(self, master_password: str, salt: bytes) -> bytes:
        """Derive 256-bit AES key using PBKDF2-HMAC-SHA256 with 600,000 iterations."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=PBKDF2_ITERATIONS
        )
        return kdf.derive(master_password.encode('utf-8'))

    def compute_auth_verifier(self, key: bytes) -> str:
        """Derive zero-knowledge auth verifier hash."""
        digest = hashes.Hash(hashes.SHA256())
        digest.update(key)
        return digest.finalize().hex()

    def encrypt_data(self, plaintext_bytes: bytes, key: bytes, nonce: bytes = None) -> tuple[bytes, bytes]:
        """Encrypt data using AES-256-GCM (returns nonce and ciphertext+tag)."""
        if nonce is None:
            nonce = secrets.token_bytes(NONCE_SIZE)
        aesgcm = AESGCM(key)
        ciphertext_and_tag = aesgcm.encrypt(nonce, plaintext_bytes, None)
        return nonce, ciphertext_and_tag

    def decrypt_data(self, ciphertext_and_tag: bytes, nonce: bytes, key: bytes) -> bytes:
        """Decrypt data using AES-256-GCM. Raises InvalidTag if tampered."""
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext_and_tag, None)

    def init_vault(self, master_password: str):
        """Create a new encrypted vault."""
        if os.path.exists(self.vault_path):
            raise FileExistsError(f"Vault already exists at '{self.vault_path}'.")

        salt = secrets.token_bytes(SALT_SIZE)
        key = self.derive_key(master_password, salt)
        auth_verifier = self.compute_auth_verifier(key)

        initial_items = [
            {
                "id": "item-1",
                "title": "CNS Academic Portal",
                "username": "student_cns",
                "password": "Initial#StrongPass99!",
                "category": "login",
                "notes": "Academic project repository and documentation.",
                "created_at": datetime.now().isoformat()
            }
        ]

        payload_bytes = json.dumps(initial_items).encode('utf-8')
        nonce, ciphertext = self.encrypt_data(payload_bytes, key)

        vault_dict = {
            "version": "2.0-CNS",
            "cipher": "AES-256-GCM",
            "kdf": {
                "algorithm": "PBKDF2-HMAC-SHA256",
                "iterations": PBKDF2_ITERATIONS,
                "salt_hex": salt.hex()
            },
            "auth_verifier_hex": auth_verifier,
            "crypto_payload": {
                "nonce_hex": nonce.hex(),
                "ciphertext_hex": ciphertext.hex()
            },
            "item_count": len(initial_items),
            "created_at": datetime.now().isoformat()
        }

        with open(self.vault_path, 'w', encoding='utf-8') as f:
            json.dump(vault_dict, f, indent=2)

        print(f"[+] Successfully initialized encrypted vault at '{self.vault_path}'!")
        print(f"[*] AES-256-GCM AEAD active with {PBKDF2_ITERATIONS:,} PBKDF2 iterations.")

    def load_vault(self, master_password: str) -> tuple[list, bytes, dict]:
        """Verify master password and decrypt vault items."""
        if not os.path.exists(self.vault_path):
            raise FileNotFoundError(f"Vault file '{self.vault_path}' not found. Run 'init' first.")

        with open(self.vault_path, 'r', encoding='utf-8') as f:
            vault_dict = json.load(f)

        salt = bytes.fromhex(vault_dict["kdf"]["salt_hex"])
        key = self.derive_key(master_password, salt)

        # Verify auth verifier
        if self.compute_auth_verifier(key) != vault_dict["auth_verifier_hex"]:
            raise PermissionError("Authentication failed: Incorrect master password!")

        nonce = bytes.fromhex(vault_dict["crypto_payload"]["nonce_hex"])
        ciphertext = bytes.fromhex(vault_dict["crypto_payload"]["ciphertext_hex"])

        try:
            decrypted_bytes = self.decrypt_data(ciphertext, nonce, key)
            items = json.loads(decrypted_bytes.decode('utf-8'))
            return items, key, vault_dict
        except Exception as e:
            raise RuntimeError(f"Cryptographic AEAD integrity check failed: {e}")

    def save_vault(self, items: list, key: bytes, vault_dict: dict):
        """Save updated items with a fresh CSPRNG nonce."""
        payload_bytes = json.dumps(items).encode('utf-8')
        fresh_nonce, fresh_ciphertext = self.encrypt_data(payload_bytes, key)

        vault_dict["crypto_payload"]["nonce_hex"] = fresh_nonce.hex()
        vault_dict["crypto_payload"]["ciphertext_hex"] = fresh_ciphertext.hex()
        vault_dict["item_count"] = len(items)
        vault_dict["updated_at"] = datetime.now().isoformat()

        with open(self.vault_path, 'w', encoding='utf-8') as f:
            json.dump(vault_dict, f, indent=2)

    @staticmethod
    def calculate_entropy(password: str) -> float:
        """Calculate Shannon entropy bits for a password."""
        if not password:
            return 0.0
        pool_size = 0
        if any(c.islower() for c in password): pool_size += 26
        if any(c.isupper() for c in password): pool_size += 26
        if any(c.isdigit() for c in password): pool_size += 10
        if any(not c.isalnum() for c in password): pool_size += 33

        if pool_size == 0:
            return 0.0

        entropy = len(password) * math.log2(pool_size)
        return round(entropy, 1)

    @staticmethod
    def generate_token(length=20) -> str:
        """Generate cryptographically secure random token without bias."""
        alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%^&*()-_=+"
        return ''.join(secrets.choice(alphabet) for _ in range(length))

def main():
    parser = argparse.ArgumentParser(description="AEGIS-VAULT : CLI AES-256-GCM Password Manager (CNS Project)")
    parser.add_argument("--vault", default=DEFAULT_VAULT_FILE, help="Path to vault JSON file")

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: init
    subparsers.add_parser("init", help="Initialize a new encrypted vault")

    # Command: add
    subparsers.add_parser("add", help="Add a new secret item")

    # Command: list
    subparsers.add_parser("list", help="List all vault titles and usernames")

    # Command: get
    sub_get = subparsers.add_parser("get", help="Retrieve and decrypt a specific password")
    sub_get.add_argument("title", help="Title or partial title to look up")

    # Command: audit
    subparsers.add_parser("audit", help="Audit vault passwords for entropy and duplicates")

    # Command: generate
    sub_gen = subparsers.add_parser("generate", help="Generate a high-entropy password")
    sub_gen.add_argument("--length", type=int, default=24, help="Password length")

    # Command: test-attack (Tampering attack demonstration)
    subparsers.add_parser("test-attack", help="Simulate a bit-flipping attack on ciphertext to demonstrate AEAD tag rejection")

    args = parser.parse_args()
    cli = AegisVaultCLI(args.vault)

    if args.command == "init":
        pwd1 = getpass.getpass("Set Master Password: ")
        pwd2 = getpass.getpass("Confirm Master Password: ")
        if pwd1 != pwd2:
            print("[-] Passwords do not match!")
            sys.exit(1)
        cli.init_vault(pwd1)

    elif args.command == "add":
        pwd = getpass.getpass("Enter Master Password: ")
        try:
            items, key, vault_dict = cli.load_vault(pwd)
            title = input("Item Title: ").strip()
            username = input("Username / Email: ").strip()
            secret = getpass.getpass("Secret Password (leave blank to auto-generate): ").strip()
            if not secret:
                secret = cli.generate_token(22)
                print(f"[+] Generated password: {secret}")
            notes = input("Notes: ").strip()

            new_item = {
                "id": f"item-{secrets.token_hex(4)}",
                "title": title,
                "username": username,
                "password": secret,
                "category": "login",
                "notes": notes,
                "created_at": datetime.now().isoformat()
            }
            items.append(new_item)
            cli.save_vault(items, key, vault_dict)
            print(f"[+] Successfully encrypted and added '{title}' to vault!")
        except Exception as e:
            print(f"[-] Error: {e}")

    elif args.command == "list":
        pwd = getpass.getpass("Enter Master Password: ")
        try:
            items, _, _ = cli.load_vault(pwd)
            print("\n" + "=" * 60)
            print(f"{'TITLE':<25} {'IDENTITY':<25} {'ENTROPY':<10}")
            print("=" * 60)
            for itm in items:
                ent = cli.calculate_entropy(itm['password'])
                print(f"{itm['title']:<25} {itm.get('username', ''):<25} {ent} bits")
            print("=" * 60)
            print(f"Total: {len(items)} credentials\n")
        except Exception as e:
            print(f"[-] Error: {e}")

    elif args.command == "get":
        pwd = getpass.getpass("Enter Master Password: ")
        try:
            items, _, _ = cli.load_vault(pwd)
            query = args.title.lower()
            matches = [i for i in items if query in i['title'].lower()]
            if not matches:
                print(f"[-] No items found matching '{args.title}'.")
            else:
                for itm in matches:
                    print(f"\n[+] Title    : {itm['title']}")
                    print(f"    Username : {itm.get('username', 'N/A')}")
                    print(f"    Password : {itm['password']}")
                    print(f"    Notes    : {itm.get('notes', 'None')}")
                    print(f"    Entropy  : {cli.calculate_entropy(itm['password'])} bits\n")
        except Exception as e:
            print(f"[-] Error: {e}")

    elif args.command == "audit":
        pwd = getpass.getpass("Enter Master Password: ")
        try:
            items, _, _ = cli.load_vault(pwd)
            print("\n[*] RUNNING CRYPTOGRAPHIC VULNERABILITY AUDIT...")
            weak_count = 0
            pwd_map = {}
            for itm in items:
                ent = cli.calculate_entropy(itm['password'])
                if ent < 50:
                    print(f"[!] WEAK PASSWORD: '{itm['title']}' has only {ent} bits of entropy!")
                    weak_count += 1
                pwd_map.setdefault(itm['password'], []).append(itm['title'])

            for secret, titles in pwd_map.items():
                if len(titles) > 1:
                    print(f"[!] REUSED CREDENTIAL: Password shared between: {', '.join(titles)}")

            if weak_count == 0 and all(len(t) == 1 for t in pwd_map.values()):
                print("[+] All vault credentials passed entropy and unique-key checks!")
        except Exception as e:
            print(f"[-] Error: {e}")

    elif args.command == "generate":
        token = cli.generate_token(args.length)
        ent = cli.calculate_entropy(token)
        print(f"[+] Generated Token: {token}")
        print(f"[*] Shannon Entropy : {ent} bits (Unbreakable)")

    elif args.command == "test-attack":
        print("\n" + "=" * 70)
        print("CNS LAB DEMO: CIPHERTEXT BIT-FLIPPING ATTACK ON AES-256-GCM")
        print("=" * 70)
        # Generate random key and plaintext
        ephemeral_key = secrets.token_bytes(32)
        plaintext = b"CONFIDENTIAL_PAYLOAD_TRANSFER_AUTHENTICATED"
        nonce, ciphertext_and_tag = cli.encrypt_data(plaintext, ephemeral_key)

        print(f"1. Original Plaintext : {plaintext.decode()}")
        print(f"2. Original Ciphertext: {ciphertext_and_tag.hex()[:40]}... (length: {len(ciphertext_and_tag)} bytes)")

        # Attacker flips 1 bit in transit
        tampered_bytes = bytearray(ciphertext_and_tag)
        target_byte = 5
        tampered_bytes[target_byte] ^= 0x01
        print(f"\n[*] [ATTACK] Man-in-the-Middle flipped bit 0 at byte index {target_byte}!")
        print(f"3. Tampered Ciphertext: {tampered_bytes.hex()[:40]}...")

        # Recipient attempts decryption
        print("\n[*] Recipient attempting AES-256-GCM AEAD decryption...")
        try:
            cli.decrypt_data(bytes(tampered_bytes), nonce, ephemeral_key)
            print("[-] VULNERABILITY: Tampered data was accepted! (Should never happen)")
        except Exception as e:
            print(f"[+] [SUCCESS] AEAD PROTECTED! Decryption halted immediately with error:")
            print(f"    --> {type(e).__name__}: Tag mismatch or cryptographic tampering detected!")
            print("[*] Explanation: AES-GCM GHASH tag verification failed over Galois Field GF(2^128).")
            print("    The tampered packet was rejected before any corrupted plaintext was processed.\n")

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
