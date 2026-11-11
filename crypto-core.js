/**
 * ==============================================================================
 * AEGIS-VAULT : CRYPTOGRAPHIC CORE ENGINE
 * ==============================================================================
 * Course / Topic : Cryptography and Network Security (CNS)
 * Implementation : AES-256-GCM Authenticated Encryption with PBKDF2-HMAC-SHA256
 * Security Standard: NIST SP 800-38D (GCM) & RFC 8018 (PKCS#5 PBKDF2)
 *
 * Core Principles Implemented:
 * 1. Zero-Knowledge Architecture (No plaintext or master password storage)
 * 2. Authenticated Encryption with Associated Data (AEAD) - Integrity + Secrecy
 * 3. CSPRNG Random Salt (256-bit) and Nonce/IV (96-bit)
 * 4. High Iteration Count KDF (600,000 rounds) mitigating GPU/ASIC brute-force
 * 5. Rejection Sampling to eliminate Modulo Bias in Password Generation
 * ==============================================================================
 */

class AegisCryptoCore {
    constructor() {
        this.PBKDF2_ITERATIONS = 600000; // OWASP recommended iteration baseline
        this.SALT_BYTES = 32;            // 256 bits salt for PBKDF2
        this.IV_BYTES = 12;              // 96 bits nonce standard for AES-GCM
        this.TAG_LENGTH_BITS = 128;      // 128-bit authentication tag
        this.activeKey = null;           // Stored ONLY in volatile memory while vault is unlocked
        this.currentVaultMeta = null;    // Nonce, Salt, and Auth Verifier metadata
    }

    /* --------------------------------------------------------------------------
     * 1. BYTE CONVERSION & UTILITY HELPERS
     * -------------------------------------------------------------------------- */

    /**
     * Convert an ArrayBuffer or Uint8Array to a Hexadecimal string.
     */
    bufferToHex(buffer) {
        const byteArray = new Uint8Array(buffer);
        let hex = '';
        for (let i = 0; i < byteArray.length; i++) {
            hex += byteArray[i].toString(16).padStart(2, '0');
        }
        return hex;
    }

    /**
     * Convert a Hexadecimal string to Uint8Array.
     */
    hexToBuffer(hex) {
        if (!hex || hex.length % 2 !== 0) {
            throw new Error('Invalid hexadecimal string format.');
        }
        const bytes = new Uint8Array(hex.length / 2);
        for (let i = 0; i < hex.length; i += 2) {
            bytes[i / 2] = parseInt(hex.substring(i, i + 2), 16);
        }
        return bytes;
    }

    /**
     * Convert UTF-8 string to Uint8Array buffer.
     */
    stringToBuffer(str) {
        return new TextEncoder().encode(str);
    }

    /**
     * Convert Uint8Array buffer to UTF-8 string.
     */
    bufferToString(buffer) {
        return new TextDecoder().decode(buffer);
    }

    /**
     * Generate Cryptographically Secure Random Bytes using CSPRNG.
     */
    getRandomBytes(length) {
        const bytes = new Uint8Array(length);
        window.crypto.getRandomValues(bytes);
        return bytes;
    }

    /* --------------------------------------------------------------------------
     * 2. KEY DERIVATION FUNCTION (PBKDF2-HMAC-SHA256)
     * -------------------------------------------------------------------------- */

    /**
     * Derives an AES-GCM-256 Key and an Auth Verifier from a Master Password.
     * Uses Domain Separation to generate two mathematically independent keys:
     * - Encryption Key (used exclusively for AES-GCM encrypt/decrypt)
     * - Verifier Hash (stored to verify master password without leaking encryption key)
     */
    async deriveVaultKeys(masterPassword, saltBytes, iterations = this.PBKDF2_ITERATIONS) {
        const passwordBuffer = this.stringToBuffer(masterPassword);

        // Import the raw master password into a base key
        const baseKey = await window.crypto.subtle.importKey(
            'raw',
            passwordBuffer,
            { name: 'PBKDF2' },
            false,
            ['deriveKey', 'deriveBits']
        );

        // Derive 512 bits (64 bytes) total:
        // First 32 bytes (256 bits) = AES-GCM Encryption Key
        // Next 32 bytes (256 bits)  = Authentication Verification Pre-image
        const derivedBits = await window.crypto.subtle.deriveBits(
            {
                name: 'PBKDF2',
                salt: saltBytes,
                iterations: iterations,
                hash: 'SHA-256'
            },
            baseKey,
            512
        );

        const encKeyBytes = new Uint8Array(derivedBits, 0, 32);
        const authKeyBytes = new Uint8Array(derivedBits, 32, 32);

        // Import the 256-bit encryption key into WebCrypto AES-GCM
        const aesKey = await window.crypto.subtle.importKey(
            'raw',
            encKeyBytes,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );

        // Compute SHA-256 hash of authKeyBytes as Auth Verifier
        const authVerifierBuffer = await window.crypto.subtle.digest('SHA-256', authKeyBytes);
        const authVerifierHex = this.bufferToHex(authVerifierBuffer);

        return {
            aesKey: aesKey,
            authVerifierHex: authVerifierHex
        };
    }

    /* --------------------------------------------------------------------------
     * 3. AES-256-GCM ENCRYPTION & DECRYPTION (AEAD)
     * -------------------------------------------------------------------------- */

    /**
     * Encrypts plaintext data using AES-256-GCM.
     * Returns ciphertext and tag embedded along with the generated IV.
     * @param {string|object} plaintextData - Raw text or JS object to encrypt
     * @param {CryptoKey} key - AES-GCM 256-bit CryptoKey
     * @param {Uint8Array} [customIv] - Optional explicit IV (for lab demo)
     */
    async encryptAESGCM(plaintextData, key = this.activeKey, customIv = null) {
        if (!key) {
            throw new Error('Vault is locked. Encryption key is not available in volatile memory.');
        }

        const plaintextStr = typeof plaintextData === 'string' ? plaintextData : JSON.stringify(plaintextData);
        const plaintextBytes = this.stringToBuffer(plaintextStr);

        // Generate a 96-bit (12 bytes) fresh initialization vector / nonce
        const iv = customIv || this.getRandomBytes(this.IV_BYTES);

        // Encrypt with AES-GCM (W3C standard appends the 128-bit auth tag to ciphertext)
        const encryptedBuffer = await window.crypto.subtle.encrypt(
            {
                name: 'AES-GCM',
                iv: iv,
                tagLength: this.TAG_LENGTH_BITS
            },
            key,
            plaintextBytes
        );

        const encryptedBytes = new Uint8Array(encryptedBuffer);
        // The last 16 bytes is the authentication tag
        const cipherOnlyBytes = encryptedBytes.slice(0, encryptedBytes.length - 16);
        const tagBytes = encryptedBytes.slice(encryptedBytes.length - 16);

        return {
            ivHex: this.bufferToHex(iv),
            ciphertextHex: this.bufferToHex(cipherOnlyBytes),
            tagHex: this.bufferToHex(tagBytes),
            fullCiphertextHex: this.bufferToHex(encryptedBytes)
        };
    }

    /**
     * Decrypts AES-256-GCM ciphertext. Throws an error if ciphertext or tag was tampered.
     * @param {string} fullCiphertextHex - Hex of ciphertext + 16 bytes tag
     * @param {string} ivHex - Hex of 12 bytes IV
     * @param {CryptoKey} key - AES-GCM CryptoKey
     */
    async decryptAESGCM(fullCiphertextHex, ivHex, key = this.activeKey) {
        if (!key) {
            throw new Error('Vault is locked. Master key is absent.');
        }

        const fullCipherBytes = this.hexToBuffer(fullCiphertextHex);
        const ivBytes = this.hexToBuffer(ivHex);

        try {
            const decryptedBuffer = await window.crypto.subtle.decrypt(
                {
                    name: 'AES-GCM',
                    iv: ivBytes,
                    tagLength: this.TAG_LENGTH_BITS
                },
                key,
                fullCipherBytes
            );

            const decryptedStr = this.bufferToString(decryptedBuffer);
            try {
                return JSON.parse(decryptedStr);
            } catch {
                return decryptedStr;
            }
        } catch (error) {
            // Cryptographic authentication failure: Tag mismatch or corrupted bits
            throw new Error('CRYPTOGRAPHIC_INTEGRITY_FAILURE: AES-GCM authentication tag mismatch or corrupted ciphertext! Tampering detected.');
        }
    }

    /* --------------------------------------------------------------------------
     * 4. VAULT INITIALIZATION, UNLOCKING & MEMORY PURGE
     * -------------------------------------------------------------------------- */

    /**
     * Create a brand new encrypted vault container with initial seed data.
     */
    async initializeVault(masterPassword, initialItems = []) {
        const saltBytes = this.getRandomBytes(this.SALT_BYTES);
        const { aesKey, authVerifierHex } = await this.deriveVaultKeys(masterPassword, saltBytes);

        this.activeKey = aesKey;

        // Encrypt the initial items array
        const encryptionResult = await this.encryptAESGCM(initialItems, aesKey);

        const vaultEnvelope = {
            version: '2.0-CNS',
            cipherSuite: 'AES-256-GCM',
            kdf: {
                algorithm: 'PBKDF2-HMAC-SHA256',
                iterations: this.PBKDF2_ITERATIONS,
                saltHex: this.bufferToHex(saltBytes)
            },
            authVerifierHex: authVerifierHex,
            cryptoPayload: {
                ivHex: encryptionResult.ivHex,
                fullCiphertextHex: encryptionResult.fullCiphertextHex,
                tagHex: encryptionResult.tagHex
            },
            metadata: {
                createdAt: new Date().toISOString(),
                lastModified: new Date().toISOString(),
                itemCount: initialItems.length
            }
        };

        this.currentVaultMeta = vaultEnvelope;
        return vaultEnvelope;
    }

    /**
     * Unlocks an existing vault envelope using the user's master password.
     */
    async unlockVault(masterPassword, vaultEnvelope) {
        const saltBytes = this.hexToBuffer(vaultEnvelope.kdf.saltHex);
        const iterations = vaultEnvelope.kdf.iterations || this.PBKDF2_ITERATIONS;

        const { aesKey, authVerifierHex } = await this.deriveVaultKeys(masterPassword, saltBytes, iterations);

        // Verify master password authentication hash
        if (authVerifierHex !== vaultEnvelope.authVerifierHex) {
            throw new Error('INCORRECT_MASTER_PASSWORD: Derived authentication verifier does not match.');
        }

        // Decrypt the payload
        const decryptedItems = await this.decryptAESGCM(
            vaultEnvelope.cryptoPayload.fullCiphertextHex,
            vaultEnvelope.cryptoPayload.ivHex,
            aesKey
        );

        // Keep key in volatile memory
        this.activeKey = aesKey;
        this.currentVaultMeta = vaultEnvelope;

        return decryptedItems;
    }

    /**
     * Saves updated items back to the vault envelope with a fresh unique IV.
     */
    async saveVault(items) {
        if (!this.activeKey || !this.currentVaultMeta) {
            throw new Error('Cannot save: Vault is locked or uninitialized.');
        }

        // Each encryption MUST use a freshly generated CSPRNG IV to prevent nonce reuse attacks
        const encryptionResult = await this.encryptAESGCM(items, this.activeKey);

        this.currentVaultMeta.cryptoPayload = {
            ivHex: encryptionResult.ivHex,
            fullCiphertextHex: encryptionResult.fullCiphertextHex,
            tagHex: encryptionResult.tagHex
        };
        this.currentVaultMeta.metadata.lastModified = new Date().toISOString();
        this.currentVaultMeta.metadata.itemCount = items.length;

        return this.currentVaultMeta;
    }

    /**
     * Purges the encryption key from RAM and locks the vault.
     */
    lockVault() {
        this.activeKey = null;
        this.currentVaultMeta = null;
    }

    isUnlocked() {
        return this.activeKey !== null;
    }

    /* --------------------------------------------------------------------------
     * 5. CRYPTOGRAPHIC ENTROPY & SECURITY EVALUATOR
     * -------------------------------------------------------------------------- */

    /**
     * Calculates Shannon entropy in bits for a password:
     * H = L * log2(N)
     * where L is password length, N is character set cardinality.
     * Also factors in character frequency and redundancy penalties.
     */
    calculateEntropy(password) {
        if (!password || password.length === 0) {
            return {
                bits: 0,
                rating: 'Empty',
                color: '#ef4444',
                poolSize: 0,
                crackTimeStr: '0 seconds'
            };
        }

        let poolSize = 0;
        const hasLower = /[a-z]/.test(password);
        const hasUpper = /[A-Z]/.test(password);
        const hasDigit = /[0-9]/.test(password);
        const hasSymbol = /[^a-zA-Z0-9]/.test(password);

        if (hasLower) poolSize += 26;
        if (hasUpper) poolSize += 26;
        if (hasDigit) poolSize += 10;
        if (hasSymbol) poolSize += 33;

        // Base entropy
        const len = password.length;
        let bits = len * (Math.log2(poolSize || 1));

        // Repetition and pattern penalty
        const uniqueChars = new Set(password.split('')).size;
        const redundancyFactor = uniqueChars / len;
        bits = bits * (0.6 + 0.4 * redundancyFactor);

        // Sequence penalties (e.g. "12345", "abc", "qwerty")
        if (/(?:abc|bcd|cde|def|efg|123|234|345|456|567|678|789|012|qwerty|asdf)/i.test(password)) {
            bits = Math.max(10, bits - 15);
        }

        bits = Math.round(bits * 10) / 10;

        let rating = 'Very Weak';
        let color = '#ef4444'; // Red
        if (bits >= 35 && bits < 55) {
            rating = 'Weak';
            color = '#f97316'; // Orange
        } else if (bits >= 55 && bits < 75) {
            rating = 'Moderate';
            color = '#eab308'; // Yellow
        } else if (bits >= 75 && bits < 95) {
            rating = 'Strong';
            color = '#10b981'; // Green
        } else if (bits >= 95) {
            rating = 'Very Strong';
            color = '#06b6d4'; // Cyan
        }

        const crackTimes = this.estimateCrackTime(bits);

        return {
            bits,
            rating,
            color,
            poolSize,
            crackTimes,
            checks: {
                hasLower,
                hasUpper,
                hasDigit,
                hasSymbol,
                length: len,
                uniqueRatio: Math.round(redundancyFactor * 100)
            }
        };
    }

    /**
     * Estimates crack time against various threat levels based on bits of entropy:
     * T = 2^(bits) / Speed
     */
    estimateCrackTime(bits) {
        const combinations = Math.pow(2, bits);

        // 1. Online web throttled (100 guesses / sec)
        const onlineSec = combinations / 100;
        // 2. Fast offline single GPU (10^7 guesses / sec)
        const fastGpuSec = combinations / 1e7;
        // 3. High-end Distributed GPU Cluster / Hashcat (10^11 hashes / sec)
        const clusterSec = combinations / 1e11;
        // 4. Quantum / Supercomputer Future Threat (10^15 operations / sec)
        const supercompSec = combinations / 1e15;

        return {
            online: this.formatTimeSpan(onlineSec),
            fastGpu: this.formatTimeSpan(fastGpuSec),
            cluster: this.formatTimeSpan(clusterSec),
            supercomputer: this.formatTimeSpan(supercompSec)
        };
    }

    formatTimeSpan(seconds) {
        if (!isFinite(seconds) || seconds > 1e15) return 'Centuries (Mathematically Infeasible)';
        if (seconds < 0.001) return 'Instantaneous (< 1 millisecond)';
        if (seconds < 1) return '< 1 second';
        if (seconds < 60) return `${Math.round(seconds)} seconds`;
        const minutes = seconds / 60;
        if (minutes < 60) return `${Math.round(minutes)} minutes`;
        const hours = minutes / 60;
        if (hours < 24) return `${Math.round(hours)} hours`;
        const days = hours / 24;
        if (days < 365) return `${Math.round(days)} days`;
        const years = days / 365.25;
        if (years < 1000) return `${Math.round(years)} years`;
        if (years < 1e6) return `${(years / 1000).toFixed(1)} thousand years`;
        if (years < 1e9) return `${(years / 1e6).toFixed(1)} million years`;
        return `${(years / 1e9).toFixed(1)} billion years`;
    }

    /* --------------------------------------------------------------------------
     * 6. CSPRNG PASSWORD GENERATOR & DICEWARE PASSPHRASE
     * -------------------------------------------------------------------------- */

    /**
     * Generates a random cryptographic password without modulo bias.
     */
    generatePassword(options = {}) {
        const {
            length = 20,
            useLower = true,
            useUpper = true,
            useDigits = true,
            useSymbols = true,
            avoidAmbiguous = true
        } = options;

        let lowerChars = 'abcdefghijklmnopqrstuvwxyz';
        let upperChars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        let digitChars = '0123456789';
        let symbolChars = '!@#$%^&*()_+-=[]{}|;:,.<>?';

        if (avoidAmbiguous) {
            // Remove l, 1, I, o, 0, O, `, ~, ', "
            lowerChars = lowerChars.replace(/[lo]/g, '');
            upperChars = upperChars.replace(/[IO]/g, '');
            digitChars = digitChars.replace(/[01]/g, '');
            symbolChars = symbolChars.replace(/[`'"|]/g, '');
        }

        let charPool = '';
        const guaranteed = [];

        if (useLower) {
            charPool += lowerChars;
            guaranteed.push(this.getRandomChar(lowerChars));
        }
        if (useUpper) {
            charPool += upperChars;
            guaranteed.push(this.getRandomChar(upperChars));
        }
        if (useDigits) {
            charPool += digitChars;
            guaranteed.push(this.getRandomChar(digitChars));
        }
        if (useSymbols) {
            charPool += symbolChars;
            guaranteed.push(this.getRandomChar(symbolChars));
        }

        if (!charPool) {
            charPool = lowerChars + digitChars;
        }

        const remainingLength = Math.max(0, length - guaranteed.length);
        const randomChars = [];

        // Uniform rejection sampling to avoid modulo bias
        const poolSize = charPool.length;
        const maxValidByte = 256 - (256 % poolSize);

        while (randomChars.length < remainingLength) {
            const randomBytes = this.getRandomBytes(remainingLength * 2);
            for (let i = 0; i < randomBytes.length && randomChars.length < remainingLength; i++) {
                const byte = randomBytes[i];
                if (byte < maxValidByte) {
                    randomChars.push(charPool[byte % poolSize]);
                }
            }
        }

        // Combine guaranteed chars and random chars, then Fisher-Yates shuffle
        const allChars = [...guaranteed, ...randomChars];
        for (let i = allChars.length - 1; i > 0; i--) {
            const randIdx = this.getRandomInt(0, i);
            [allChars[i], allChars[randIdx]] = [allChars[randIdx], allChars[i]];
        }

        return allChars.join('');
    }

    /**
     * Generates a Diceware-style passphrase using EFF wordlist words.
     */
    generatePassphrase(wordCount = 5, delimiter = '-', capitalize = true) {
        const words = [
            'galaxy', 'matrix', 'cipher', 'quantum', 'shield', 'enigma', 'fortress',
            'sentinel', 'vector', 'horizon', 'nebula', 'protocol', 'zenith', 'pulse',
            'glacier', 'vortex', 'obsidian', 'citadel', 'phoenix', 'cascade', 'aurora',
            'titan', 'beacon', 'bastion', 'vanguard', 'oracle', 'crypto', 'shadow',
            'starlight', 'monolith', 'element', 'prism', 'valiant', 'solace', 'harbor',
            'phantom', 'eclipse', 'dynamo', 'odyssey', 'kinetic', 'radiant', 'apex'
        ];

        const selected = [];
        for (let i = 0; i < wordCount; i++) {
            const idx = this.getRandomInt(0, words.length - 1);
            let word = words[idx];
            if (capitalize) {
                word = word.charAt(0).toUpperCase() + word.slice(1);
            }
            selected.push(word);
        }

        return selected.join(delimiter);
    }

    getRandomChar(pool) {
        const idx = this.getRandomInt(0, pool.length - 1);
        return pool[idx];
    }

    getRandomInt(min, max) {
        const range = max - min + 1;
        const maxValidByte = 256 - (256 % range);
        while (true) {
            const byte = this.getRandomBytes(1)[0];
            if (byte < maxValidByte) {
                return min + (byte % range);
            }
        }
    }

    /* --------------------------------------------------------------------------
     * 7. k-ANONYMITY ZERO-KNOWLEDGE BREACH CHECKER
     * -------------------------------------------------------------------------- */

    /**
     * Computes the SHA-1 hash of a password for k-Anonymity breach lookup.
     * In the real HaveIBeenPwned API, only the first 5 characters (prefix)
     * are ever sent over the network, completely preserving client privacy!
     */
    async checkBreachStatus(password) {
        const buffer = this.stringToBuffer(password);
        const hashBuffer = await window.crypto.subtle.digest('SHA-1', buffer);
        const sha1 = this.bufferToHex(hashBuffer).toUpperCase();
        const prefix = sha1.substring(0, 5);
        const suffix = sha1.substring(5);

        // Curated known compromised common hashes / patterns for local offline CNS demo
        const knownCompromisedHashes = {
            '5BAA6': '1E4C9B93F3F0682250B6CF8331B7EE68FD8', // "password"
            '7C4A8': 'D09CA3762AF61E59520943DC26494F8941B', // "123456"
            'F359E': '92B7FE525A87FD1A9A9C24A58CF4D618E7B', // "admin"
            'E5E9F': 'A1BA31ECD1AE84F75CAAA474F3A663F05F4', // "secret"
            '356A1': '92B7913B04C54574D18C28D46E6395428AB', // "1"
            'B1B37': '73A05C0ED0176787A4B1EFA840EC5A3D002'  // "password123"
        };

        const isKnownPwned = knownCompromisedHashes[prefix] === suffix;

        return {
            sha1,
            prefix,
            suffix,
            isCompromised: isKnownPwned,
            privacyNote: `k-Anonymity Model: Only prefix (${prefix}) would be sent to the breach database. The suffix (${suffix}) stays strictly on the client!`
        };
    }
}

// Export singleton instance to window object for web access
window.AegisCrypto = new AegisCryptoCore();
