package com.noise.protocol.crypto

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * SHA-256 based hash functions for Noise protocol.
 */
object NoiseHash {
    const val HASHLEN = 32
    const val BLOCKLEN = 64

    fun hash(data: ByteArray): ByteArray =
        java.security.MessageDigest.getInstance("SHA-256").digest(data)

    fun hmacHash(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(data)
    }

    /**
     * HKDF per Noise spec: chainingKey as salt, inputKeyMaterial as IKM.
     * Returns 2 or 3 outputs of HASHLEN bytes.
     */
    fun hkdf(
        chainingKey: ByteArray,
        inputKeyMaterial: ByteArray,
        numOutputs: Int
    ): List<ByteArray> {
        val tempKey = hmacHash(chainingKey, inputKeyMaterial)
        val output1 = hmacHash(tempKey, byteArrayOf(0x01))
        val output2 = hmacHash(tempKey, output1 + byteArrayOf(0x02))
        if (numOutputs == 2) return listOf(output1, output2)
        val output3 = hmacHash(tempKey, output2 + byteArrayOf(0x03))
        return listOf(output1, output2, output3)
    }
}

/**
 * SHA-512 based hash functions for Noise protocol.
 */
object NoiseHashSHA512 {
    const val HASHLEN = 64
    const val BLOCKLEN = 128

    fun hash(data: ByteArray): ByteArray =
        java.security.MessageDigest.getInstance("SHA-512").digest(data)

    fun hmacHash(key: ByteArray, data: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA512")
        mac.init(SecretKeySpec(key, "HmacSHA512"))
        return mac.doFinal(data)
    }
}
