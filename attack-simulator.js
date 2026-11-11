/**
 * ==============================================================================
 * AEGIS-VAULT : NETWORK SECURITY & CRYPTOGRAPHIC ATTACK SIMULATOR
 * ==============================================================================
 * Course / Topic : Cryptography and Network Security (CNS)
 * Interactive Demonstrations:
 * 1. Bit-Flipping / Ciphertext Tampering Attack (AEAD Integrity verification)
 * 2. Nonce-Reuse & Replay Attack Defense (GCM "Forbidden Attack" prevention)
 * 3. KDF Work-Factor & GPU Cluster Dictionary Attack Benchmark
 * ==============================================================================
 */

class AttackSimulator {
    constructor(cryptoCore) {
        this.crypto = cryptoCore;
    }

    /**
     * Demonstrates Ciphertext Bit-Flipping Attack.
     * Takes a valid encrypted message, alters 1 or more bits in transit,
     * and shows whether the cipher successfully rejects the altered ciphertext.
     */
    async simulateBitFlippingAttack(originalPlaintext, byteIndexToFlip = 0) {
        // Step 1: Encrypt plaintext using a fresh ephemeral AES-256-GCM key
        const rawKey = this.crypto.getRandomBytes(32);
        const key = await window.crypto.subtle.importKey(
            'raw',
            rawKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );

        const encrypted = await this.crypto.encryptAESGCM(originalPlaintext, key);
        const originalFullHex = encrypted.fullCiphertextHex;

        // Step 2: Simulate malicious interceptor flipping 1 bit
        const cipherBytes = this.crypto.hexToBuffer(originalFullHex);
        const targetByte = Math.min(byteIndexToFlip, cipherBytes.length - 1);
        const originalByteValue = cipherBytes[targetByte];

        // Flip bit 0 (XOR with 0x01)
        cipherBytes[targetByte] ^= 0x01;
        const tamperedByteValue = cipherBytes[targetByte];
        const tamperedFullHex = this.crypto.bufferToHex(cipherBytes);

        // Step 3: Attempt decryption on recipient side
        let decryptionStatus = 'UNKNOWN';
        let recoveredText = null;
        let errorMessage = null;

        try {
            recoveredText = await this.crypto.decryptAESGCM(tamperedFullHex, encrypted.ivHex, key);
            decryptionStatus = 'VULNERABLE'; // Should never happen in AES-GCM
        } catch (err) {
            decryptionStatus = 'BLOCKED_BY_AEAD';
            errorMessage = err.message;
        }

        return {
            originalPlaintext,
            ivHex: encrypted.ivHex,
            originalFullHex,
            tamperedFullHex,
            targetByteIndex: targetByte,
            originalByteHex: originalByteValue.toString(16).padStart(2, '0').toUpperCase(),
            tamperedByteHex: tamperedByteValue.toString(16).padStart(2, '0').toUpperCase(),
            authTagHex: encrypted.tagHex,
            decryptionStatus,
            recoveredText,
            errorMessage,
            cnsExplanation: `AES-GCM computes a 128-bit Galois Message Authentication Code (GMAC) over the ciphertext and IV using GHASH in GF(2^128). Flipping a single bit causes the GMAC tag verification to fail during polynomial evaluation, rejecting the tampered ciphertext before any unauthenticated plaintext is exposed to memory!`
        };
    }

    /**
     * Demonstrates Nonce-Reuse Danger & Nonce Freshness
     * In AES-GCM, reusing a (Key, Nonce/IV) pair is fatal:
     * - C1 = P1 XOR Keystream
     * - C2 = P2 XOR Keystream
     * - C1 XOR C2 = P1 XOR P2 (Plaintext XOR leakage)
     * - Allows recovery of the GMAC authentication subkey H!
     */
    async simulateNonceReuseVulnerability(message1, message2) {
        const rawKey = this.crypto.getRandomBytes(32);
        const key = await window.crypto.subtle.importKey(
            'raw',
            rawKey,
            { name: 'AES-GCM', length: 256 },
            false,
            ['encrypt', 'decrypt']
        );

        // DELIBERATELY REUSE THE SAME 96-BIT IV
        const staticIv = this.crypto.getRandomBytes(12);

        const enc1 = await this.crypto.encryptAESGCM(message1, key, staticIv);
        const enc2 = await this.crypto.encryptAESGCM(message2, key, staticIv);

        const c1Bytes = this.crypto.hexToBuffer(enc1.ciphertextHex);
        const c2Bytes = this.crypto.hexToBuffer(enc2.ciphertextHex);

        const minLen = Math.min(c1Bytes.length, c2Bytes.length);
        const xorStream = new Uint8Array(minLen);
        for (let i = 0; i < minLen; i++) {
            xorStream[i] = c1Bytes[i] ^ c2Bytes[i];
        }

        return {
            message1,
            message2,
            reusedIvHex: this.crypto.bufferToHex(staticIv),
            c1Hex: enc1.ciphertextHex,
            c2Hex: enc2.ciphertextHex,
            c1XorC2Hex: this.crypto.bufferToHex(xorStream),
            cnsExplanation: `CRITICAL CNS PRINCIPLE: In Counter mode (CTR) ciphers like AES-GCM, reusing an IV across two encryptions with the same key generates the exact same keystream! An eavesdropper computes C1 ⊕ C2 = P1 ⊕ P2, eliminating encryption entirely and enabling crib-dragging and GMAC subkey forgery. AegisVault uses a 96-bit CSPRNG unique IV per write operation, guaranteeing IV collision probability < 2^-32 according to NIST SP 800-38D.`
        };
    }

    /**
     * Live KDF Iteration Work-Factor Benchmark.
     * Measures client execution time for different iteration counts
     * and calculates how fast a 100-GPU cluster could attack them.
     */
    async benchmarkKdfWorkFactor(password = 'MasterSecret@2026') {
        const testCounts = [1000, 10000, 50000, 100000];
        const results = [];
        const salt = this.crypto.getRandomBytes(16);

        const baseKey = await window.crypto.subtle.importKey(
            'raw',
            this.crypto.stringToBuffer(password),
            { name: 'PBKDF2' },
            false,
            ['deriveBits']
        );

        for (const iters of testCounts) {
            const start = performance.now();
            await window.crypto.subtle.deriveBits(
                {
                    name: 'PBKDF2',
                    salt: salt,
                    iterations: iters,
                    hash: 'SHA-256'
                },
                baseKey,
                256
            );
            const elapsedMs = performance.now() - start;

            // GPU cluster comparison (8x RTX 4090 Hashcat cluster)
            // An RTX 4090 can compute ~3.2 x 10^9 raw MD5 / sec,
            // but for PBKDF2-HMAC-SHA256, speed scales inversely with iteration count:
            // GPU Speed = 15,000,000 / (iterations) attempts per sec per GPU.
            // For 8 GPUs = 120,000,000 / (iterations) attempts/sec.
            const gpuClusterAttemptsPerSec = Math.max(1, Math.round(120000000 / iters));

            results.push({
                iterations: iters,
                clientTimeMs: Math.round(elapsedMs * 10) / 10,
                gpuAttemptsPerSec: gpuClusterAttemptsPerSec.toLocaleString(),
                relativeCost: `${(iters / 1000)}x harder`
            });
        }

        // Extrapolate for 600,000 iterations
        const estimated600kMs = Math.round((results[results.length - 1].clientTimeMs / 100000) * 600000);
        const estimated600kGpu = Math.round(120000000 / 600000);

        results.push({
            iterations: 600000,
            clientTimeMs: `~${estimated600kMs} (OWASP Standard)`,
            gpuAttemptsPerSec: `${estimated600kGpu.toLocaleString()} attempts/sec`,
            relativeCost: '600x harder (Baseline)'
        });

        return results;
    }
}

window.AegisAttackSimulator = new AttackSimulator(window.AegisCrypto);
