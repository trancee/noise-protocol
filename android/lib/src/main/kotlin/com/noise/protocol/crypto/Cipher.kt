package com.noise.protocol.crypto

import java.nio.ByteBuffer
import java.nio.ByteOrder
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * ChaCha20-Poly1305 AEAD cipher for Noise protocol.
 * Nonce format: 4 zero bytes + 8 bytes little-endian counter.
 */
object NoiseCipher {
    /** AEAD encrypt. Returns ciphertext || 16-byte tag. */
    fun encrypt(k: ByteArray, n: Long, ad: ByteArray, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        val nonce = makeNonce(n)
        // ChaCha20-Poly1305 uses IvParameterSpec-compatible 12-byte nonce
        val spec = javax.crypto.spec.IvParameterSpec(nonce)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(k, "ChaCha20-Poly1305"), spec)
        cipher.updateAAD(ad)
        return cipher.doFinal(plaintext)
    }

    /** AEAD decrypt. Throws on authentication failure. */
    fun decrypt(k: ByteArray, n: Long, ad: ByteArray, ciphertext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("ChaCha20-Poly1305")
        val nonce = makeNonce(n)
        val spec = javax.crypto.spec.IvParameterSpec(nonce)
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(k, "ChaCha20-Poly1305"), spec)
        cipher.updateAAD(ad)
        return cipher.doFinal(ciphertext)
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
    /** AEAD encrypt. Returns ciphertext || 16-byte tag. */
    fun encrypt(k: ByteArray, n: Long, ad: ByteArray, plaintext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        val nonce = makeNonce(n)
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(k, "AES"), GCMParameterSpec(128, nonce))
        cipher.updateAAD(ad)
        return cipher.doFinal(plaintext)
    }

    /** AEAD decrypt. Throws on authentication failure. */
    fun decrypt(k: ByteArray, n: Long, ad: ByteArray, ciphertext: ByteArray): ByteArray {
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
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
