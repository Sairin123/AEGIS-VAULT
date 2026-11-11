#!/usr/bin/env python3
"""
==============================================================================
UNIT TESTS & CRYPTOGRAPHIC TEST VECTORS FOR AEGIS-VAULT
==============================================================================
Tests verify:
- PBKDF2-HMAC-SHA256 key derivation consistency & salt separation
- AES-256-GCM authenticated encryption/decryption roundtrip
- AEAD authentication tag integrity check under bit-flipping
- Nonce uniqueness property (Semantic Security / IND-CPA)
- Shannon Entropy evaluation
- File persistence & vault recovery
==============================================================================
"""

import os
import unittest
import secrets
from cryptography.exceptions import InvalidTag
from vault_cli import AegisVaultCLI

class TestAegisVaultCryptography(unittest.TestCase):
    def setUp(self):
        self.test_vault_path = "test_vault_store.json"
        self.cli = AegisVaultCLI(self.test_vault_path)
        self.master_pwd = "CNS_Test_Master_Key@2026!"

    def tearDown(self):
        if os.path.exists(self.test_vault_path):
            os.remove(self.test_vault_path)

    def test_pbkdf2_derivation_and_salt_separation(self):
        """Verify PBKDF2 produces deterministic output with identical salt, and divergent keys with different salts."""
        salt1 = b"01234567890123456789012345678901"
        salt2 = b"abcdefghijklmnopqrstuvwxyz123456"

        key1_a = self.cli.derive_key(self.master_pwd, salt1)
        key1_b = self.cli.derive_key(self.master_pwd, salt1)
        key2   = self.cli.derive_key(self.master_pwd, salt2)

        self.assertEqual(len(key1_a), 32) # 256 bits
        self.assertEqual(key1_a, key1_b, "PBKDF2 must be deterministic for identical password & salt")
        self.assertNotEqual(key1_a, key2, "Different salts must produce mathematically distinct keys")

    def test_aes_gcm_encrypt_decrypt_roundtrip(self):
        """Verify AES-256-GCM successfully decrypts valid plaintext."""
        key = secrets.token_bytes(32)
        plaintext = b"CNS_Project_Super_Confidential_Password_12345"

        nonce, ciphertext = self.cli.encrypt_data(plaintext, key)
        decrypted = self.cli.decrypt_data(ciphertext, nonce, key)

        self.assertEqual(decrypted, plaintext, "Decrypted data must strictly match original plaintext")

    def test_aead_bit_flipping_tamper_detection(self):
        """Verify that altering even a single bit in ciphertext throws InvalidTag error."""
        key = secrets.token_bytes(32)
        plaintext = b"Authenticated_Banking_Transaction_Data"

        nonce, ciphertext = self.cli.encrypt_data(plaintext, key)

        # Alter single bit in byte 0
        tampered_ciphertext = bytearray(ciphertext)
        tampered_ciphertext[0] ^= 0x01

        with self.assertRaises(InvalidTag):
            self.cli.decrypt_data(bytes(tampered_ciphertext), nonce, key)

    def test_nonce_uniqueness_semantic_security(self):
        """Verify that encrypting identical plaintext twice produces distinct ciphertexts (IND-CPA)."""
        key = secrets.token_bytes(32)
        plaintext = b"Identical_Plaintext_Message"

        nonce1, cipher1 = self.cli.encrypt_data(plaintext, key)
        nonce2, cipher2 = self.cli.encrypt_data(plaintext, key)

        self.assertNotEqual(nonce1, nonce2, "CSPRNG must generate distinct nonces")
        self.assertNotEqual(cipher1, cipher2, "Identical plaintext must encrypt to distinct ciphertexts")

    def test_shannon_entropy_calculation(self):
        """Verify Shannon entropy calculation."""
        weak = "123456"
        moderate = "Summer2026!"
        strong = "j9$Kx#99!mP@123_45qZ"

        self.assertLess(self.cli.calculate_entropy(weak), 30.0)
        self.assertGreater(self.cli.calculate_entropy(strong), 80.0)

    def test_vault_init_load_and_save_workflow(self):
        """Verify end-to-end vault initialization, authentication verifier check, and item persistence."""
        self.cli.init_vault(self.master_pwd)
        self.assertTrue(os.path.exists(self.test_vault_path))

        # Test valid unlock
        items, key, vault_dict = self.cli.load_vault(self.master_pwd)
        self.assertGreaterEqual(len(items), 1)

        # Add a new item
        new_item = {
            "id": "test-item-99",
            "title": "Test Title",
            "password": "TestPassword#123",
            "category": "login"
        }
        items.append(new_item)
        self.cli.save_vault(items, key, vault_dict)

        # Re-read and check item persistence
        reloaded_items, _, _ = self.cli.load_vault(self.master_pwd)
        self.assertEqual(len(reloaded_items), 2)
        self.assertEqual(reloaded_items[1]["title"], "Test Title")

        # Test incorrect password failure
        with self.assertRaises(PermissionError):
            self.cli.load_vault("WrongPassword#999")

if __name__ == "__main__":
    unittest.main()
