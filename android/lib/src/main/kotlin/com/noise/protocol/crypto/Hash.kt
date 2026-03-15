package com.noise.protocol.crypto

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * SHA-256 based hash functions for Noise protocol.
 */
object NoiseHash {
    const val HASHLEN = 32
    const val BLOCKLEN = 64

    private val digestLocal = ThreadLocal.withInitial {
        java.security.MessageDigest.getInstance("SHA-256")
    }
    private val macLocal = ThreadLocal.withInitial {
        Mac.getInstance("HmacSHA256")
    }

    fun hash(data: ByteArray): ByteArray = digestLocal.get().digest(data)

    fun hmacHash(key: ByteArray, data: ByteArray): ByteArray {
        val mac = macLocal.get()
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
        val output1 = hmacHash(tempKey, COUNTER_01)
        val input2 = ByteArray(output1.size + 1)
        System.arraycopy(output1, 0, input2, 0, output1.size)
        input2[output1.size] = 0x02
        val output2 = hmacHash(tempKey, input2)
        if (numOutputs == 2) return listOf(output1, output2)
        val input3 = ByteArray(output2.size + 1)
        System.arraycopy(output2, 0, input3, 0, output2.size)
        input3[output2.size] = 0x03
        val output3 = hmacHash(tempKey, input3)
        return listOf(output1, output2, output3)
    }

    private val COUNTER_01 = byteArrayOf(0x01)
}

/**
 * SHA-512 based hash functions for Noise protocol.
 */
object NoiseHashSHA512 {
    const val HASHLEN = 64
    const val BLOCKLEN = 128

    private val digestLocal = ThreadLocal.withInitial {
        java.security.MessageDigest.getInstance("SHA-512")
    }
    private val macLocal = ThreadLocal.withInitial {
        Mac.getInstance("HmacSHA512")
    }

    fun hash(data: ByteArray): ByteArray = digestLocal.get().digest(data)

    fun hmacHash(key: ByteArray, data: ByteArray): ByteArray {
        val mac = macLocal.get()
        mac.init(SecretKeySpec(key, "HmacSHA512"))
        return mac.doFinal(data)
    }
}
