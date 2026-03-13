package com.noise.protocol.state

import com.noise.protocol.NoiseException
import com.noise.protocol.crypto.CipherSuite

/**
 * Holds a cipher key and nonce counter for AEAD encryption/decryption.
 */
class CipherState(internal val suite: CipherSuite = CipherSuite.NOISE_25519_CHACHAPOLY_SHA256) {
    private var k: ByteArray? = null
    private var n: Long = 0

    fun initializeKey(key: ByteArray?) {
        k = key
        n = 0
    }

    val hasKey: Boolean get() = k != null

    fun setNonce(nonce: Long) { n = nonce }
    fun getNonce(): Long = n

    /** Encrypt with associated data. If no key is set, returns plaintext. */
    fun encryptWithAd(ad: ByteArray, plaintext: ByteArray): ByteArray {
        val key = k ?: return plaintext
        if (n >= Long.MAX_VALUE - 1) throw NoiseException.NonceExhausted()
        val ct = suite.encrypt(key, n, ad, plaintext)
        n++
        return ct
    }

    /** Decrypt with associated data. On failure, nonce is NOT incremented. */
    fun decryptWithAd(ad: ByteArray, ciphertext: ByteArray): ByteArray {
        val key = k ?: return ciphertext
        val pt = try {
            suite.decrypt(key, n, ad, ciphertext)
        } catch (e: Exception) {
            throw NoiseException.DecryptionFailed()
        }
        n++
        return pt
    }

    /** Derives a new cipher key from the current one (one-way). */
    fun rekey() {
        val key = k ?: throw NoiseException.NoKey()
        val zeros = ByteArray(32)
        val newKey = suite.encrypt(key, Long.MAX_VALUE, ByteArray(0), zeros)
        k = newKey.copyOfRange(0, 32)
    }
}
