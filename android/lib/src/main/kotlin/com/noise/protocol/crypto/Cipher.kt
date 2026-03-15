package com.noise.protocol.crypto

import java.nio.ByteBuffer
import java.nio.ByteOrder
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

import java.security.InvalidKeyException

/**
 * ChaCha20-Poly1305 AEAD cipher for Noise protocol.
 * Nonce format: 4 zero bytes + 8 bytes little-endian counter.
 */
object NoiseCipher {
    private val cipherLocal = ThreadLocal.withInitial {
        Cipher.getInstance("ChaCha20-Poly1305")
    }

    /** AEAD encrypt. Returns ciphertext || 16-byte tag. */
    fun encrypt(k: ByteArray, n: Long, ad: ByteArray, plaintext: ByteArray): ByteArray {
        val cipher = initCipher(Cipher.ENCRYPT_MODE, k, makeNonce(n))
        cipher.updateAAD(ad)
        return cipher.doFinal(plaintext)
    }

    /** AEAD decrypt. Throws on authentication failure. */
    fun decrypt(k: ByteArray, n: Long, ad: ByteArray, ciphertext: ByteArray): ByteArray {
        val cipher = initCipher(Cipher.DECRYPT_MODE, k, makeNonce(n))
        cipher.updateAAD(ad)
        return cipher.doFinal(ciphertext)
    }

    private fun initCipher(mode: Int, k: ByteArray, nonce: ByteArray): Cipher {
        val spec = javax.crypto.spec.IvParameterSpec(nonce)
        val key = SecretKeySpec(k, "ChaCha20-Poly1305")
        var cipher = cipherLocal.get()
        try {
            cipher.init(mode, key, spec)
        } catch (_: InvalidKeyException) {
            // JCA rejects same key+nonce on reused ChaCha20 instance (rekey scenario)
            cipher = Cipher.getInstance("ChaCha20-Poly1305")
            cipherLocal.set(cipher)
            cipher.init(mode, key, spec)
        }
        return cipher
    }

    /** ChaChaPoly nonce: 4 zero bytes + 8 bytes little-endian n. */
    private fun makeNonce(n: Long): ByteArray {
        val nonce = ByteArray(12)
        ByteBuffer.wrap(nonce, 4, 8)
            .order(ByteOrder.LITTLE_ENDIAN)
            .putLong(n)
        return nonce
    }
}

/**
 * AES-256-GCM AEAD cipher for Noise protocol.
 * Nonce format: 4 zero bytes + 8 bytes big-endian counter.
 */
object NoiseCipherAESGCM {
    private val cipherLocal = ThreadLocal.withInitial {
        Cipher.getInstance("AES/GCM/NoPadding")
    }

    /** AEAD encrypt. Returns ciphertext || 16-byte tag. */
    fun encrypt(k: ByteArray, n: Long, ad: ByteArray, plaintext: ByteArray): ByteArray {
        val cipher = cipherLocal.get()
        val nonce = makeNonce(n)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(k, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(ad)
        return cipher.doFinal(plaintext)
    }

    /** AEAD decrypt. Throws on authentication failure. */
    fun decrypt(k: ByteArray, n: Long, ad: ByteArray, ciphertext: ByteArray): ByteArray {
        val cipher = cipherLocal.get()
        val nonce = makeNonce(n)
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(k, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(ad)
        return cipher.doFinal(ciphertext)
    }

    /** AESGCM nonce: 4 zero bytes + 8 bytes big-endian n. */
    private fun makeNonce(n: Long): ByteArray {
        val nonce = ByteArray(12)
        ByteBuffer.wrap(nonce, 4, 8).order(ByteOrder.BIG_ENDIAN).putLong(n)
        return nonce
    }
}
