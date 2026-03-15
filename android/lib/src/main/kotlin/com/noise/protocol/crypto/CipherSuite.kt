package com.noise.protocol.crypto

import blake.hash.BLAKE2b
import blake.hash.BLAKE2s
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * Bundles all cryptographic operations for a Noise cipher suite.
 */
class CipherSuite(
    val dhName: String,
    val cipherName: String,
    val hashName: String,
    val dhlen: Int,
    val hashlen: Int,
    val blocklen: Int,
    val generateKeyPair: () -> NoiseKeyPair,
    val dh: (NoiseKeyPair, ByteArray) -> ByteArray,
    val keyPairFromPrivate: (ByteArray) -> NoiseKeyPair,
    val encrypt: (ByteArray, Long, ByteArray, ByteArray) -> ByteArray,
    val decrypt: (ByteArray, Long, ByteArray, ByteArray) -> ByteArray,
    val hash: (ByteArray) -> ByteArray,
    val hmacHash: (ByteArray, ByteArray) -> ByteArray
) {
    /** HKDF derived from hmacHash. */
    fun hkdf(chainingKey: ByteArray, inputKeyMaterial: ByteArray, numOutputs: Int): List<ByteArray> {
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

    /** Construct full protocol name. */
    fun protocolName(pattern: String): String =
        "Noise_${pattern}_${dhName}_${cipherName}_${hashName}"

    companion object {
        private val COUNTER_01 = byteArrayOf(0x01)

        // Shared DH lambdas for all X25519 suites
        private val x25519Generate: () -> NoiseKeyPair = { NoiseKeyPair.generate() }
        private val x25519DH: (NoiseKeyPair, ByteArray) -> ByteArray = { kp, pub -> kp.dh(pub) }
        private val x25519FromPrivate: (ByteArray) -> NoiseKeyPair = { NoiseKeyPair.fromPrivateKey(it) }

        // ChaChaPoly lambdas
        private val chachaEncrypt: (ByteArray, Long, ByteArray, ByteArray) -> ByteArray =
            { k, n, ad, pt -> NoiseCipher.encrypt(k, n, ad, pt) }
        private val chachaDecrypt: (ByteArray, Long, ByteArray, ByteArray) -> ByteArray =
            { k, n, ad, ct -> NoiseCipher.decrypt(k, n, ad, ct) }

        // AESGCM lambdas
        private val aesgcmEncrypt: (ByteArray, Long, ByteArray, ByteArray) -> ByteArray =
            { k, n, ad, pt -> NoiseCipherAESGCM.encrypt(k, n, ad, pt) }
        private val aesgcmDecrypt: (ByteArray, Long, ByteArray, ByteArray) -> ByteArray =
            { k, n, ad, ct -> NoiseCipherAESGCM.decrypt(k, n, ad, ct) }

        // SHA-256 lambdas
        private val sha256Hash: (ByteArray) -> ByteArray = { NoiseHash.hash(it) }
        private val sha256HmacHash: (ByteArray, ByteArray) -> ByteArray =
            { key, data -> NoiseHash.hmacHash(key, data) }

        // SHA-512 lambdas
        private val sha512Hash: (ByteArray) -> ByteArray = { NoiseHashSHA512.hash(it) }
        private val sha512HmacHash: (ByteArray, ByteArray) -> ByteArray =
            { key, data -> NoiseHashSHA512.hmacHash(key, data) }

        // BLAKE2s lambdas — streaming HMAC avoids ByteArray concatenation
        private val blake2sHash: (ByteArray) -> ByteArray = { BLAKE2s.hash(it) }
        private val blake2sHmacHash: (ByteArray, ByteArray) -> ByteArray =
            { key, data -> hmacBlake2s(key, data) }

        // BLAKE2b lambdas — streaming HMAC avoids ByteArray concatenation
        private val blake2bHash: (ByteArray) -> ByteArray = { BLAKE2b.hash(it) }
        private val blake2bHmacHash: (ByteArray, ByteArray) -> ByteArray =
            { key, data -> hmacBlake2b(key, data) }

        /** Streaming HMAC-BLAKE2s (RFC 2104) — avoids ipad+data concatenation. */
        private fun hmacBlake2s(key: ByteArray, data: ByteArray): ByteArray {
            var k = if (key.size > 64) BLAKE2s.hash(key) else key
            if (k.size < 64) k = k.copyOf(64)
            val pad = ByteArray(64)
            // Inner: BLAKE2s(ipad || data)
            for (i in 0 until 64) pad[i] = (k[i].toInt() xor 0x36).toByte()
            val innerHash = BLAKE2s.Hasher().update(pad).update(data).finalize()
            // Outer: BLAKE2s(opad || innerHash)
            for (i in 0 until 64) pad[i] = (k[i].toInt() xor 0x5c).toByte()
            return BLAKE2s.Hasher().update(pad).update(innerHash).finalize()
        }

        /** Streaming HMAC-BLAKE2b (RFC 2104) — avoids ipad+data concatenation. */
        private fun hmacBlake2b(key: ByteArray, data: ByteArray): ByteArray {
            var k = if (key.size > 128) BLAKE2b.hash(key) else key
            if (k.size < 128) k = k.copyOf(128)
            val pad = ByteArray(128)
            // Inner: BLAKE2b(ipad || data)
            for (i in 0 until 128) pad[i] = (k[i].toInt() xor 0x36).toByte()
            val innerHash = BLAKE2b.Hasher().update(pad).update(data).finalize()
            // Outer: BLAKE2b(opad || innerHash)
            for (i in 0 until 128) pad[i] = (k[i].toInt() xor 0x5c).toByte()
            return BLAKE2b.Hasher().update(pad).update(innerHash).finalize()
        }

        // --- The 8 cipher suites ---

        val NOISE_25519_CHACHAPOLY_SHA256 = CipherSuite(
            dhName = "25519", cipherName = "ChaChaPoly", hashName = "SHA256",
            dhlen = DHLEN, hashlen = 32, blocklen = 64,
            generateKeyPair = x25519Generate, dh = x25519DH, keyPairFromPrivate = x25519FromPrivate,
            encrypt = chachaEncrypt, decrypt = chachaDecrypt,
            hash = sha256Hash, hmacHash = sha256HmacHash
        )

        val NOISE_25519_CHACHAPOLY_SHA512 = CipherSuite(
            dhName = "25519", cipherName = "ChaChaPoly", hashName = "SHA512",
            dhlen = DHLEN, hashlen = 64, blocklen = 128,
            generateKeyPair = x25519Generate, dh = x25519DH, keyPairFromPrivate = x25519FromPrivate,
            encrypt = chachaEncrypt, decrypt = chachaDecrypt,
            hash = sha512Hash, hmacHash = sha512HmacHash
        )

        val NOISE_25519_CHACHAPOLY_BLAKE2S = CipherSuite(
            dhName = "25519", cipherName = "ChaChaPoly", hashName = "BLAKE2s",
            dhlen = DHLEN, hashlen = 32, blocklen = 64,
            generateKeyPair = x25519Generate, dh = x25519DH, keyPairFromPrivate = x25519FromPrivate,
            encrypt = chachaEncrypt, decrypt = chachaDecrypt,
            hash = blake2sHash, hmacHash = blake2sHmacHash
        )

        val NOISE_25519_CHACHAPOLY_BLAKE2B = CipherSuite(
            dhName = "25519", cipherName = "ChaChaPoly", hashName = "BLAKE2b",
            dhlen = DHLEN, hashlen = 64, blocklen = 128,
            generateKeyPair = x25519Generate, dh = x25519DH, keyPairFromPrivate = x25519FromPrivate,
            encrypt = chachaEncrypt, decrypt = chachaDecrypt,
            hash = blake2bHash, hmacHash = blake2bHmacHash
        )

        val NOISE_25519_AESGCM_SHA256 = CipherSuite(
            dhName = "25519", cipherName = "AESGCM", hashName = "SHA256",
            dhlen = DHLEN, hashlen = 32, blocklen = 64,
            generateKeyPair = x25519Generate, dh = x25519DH, keyPairFromPrivate = x25519FromPrivate,
            encrypt = aesgcmEncrypt, decrypt = aesgcmDecrypt,
            hash = sha256Hash, hmacHash = sha256HmacHash
        )

        val NOISE_25519_AESGCM_SHA512 = CipherSuite(
            dhName = "25519", cipherName = "AESGCM", hashName = "SHA512",
            dhlen = DHLEN, hashlen = 64, blocklen = 128,
            generateKeyPair = x25519Generate, dh = x25519DH, keyPairFromPrivate = x25519FromPrivate,
            encrypt = aesgcmEncrypt, decrypt = aesgcmDecrypt,
            hash = sha512Hash, hmacHash = sha512HmacHash
        )

        val NOISE_25519_AESGCM_BLAKE2S = CipherSuite(
            dhName = "25519", cipherName = "AESGCM", hashName = "BLAKE2s",
            dhlen = DHLEN, hashlen = 32, blocklen = 64,
            generateKeyPair = x25519Generate, dh = x25519DH, keyPairFromPrivate = x25519FromPrivate,
            encrypt = aesgcmEncrypt, decrypt = aesgcmDecrypt,
            hash = blake2sHash, hmacHash = blake2sHmacHash
        )

        val NOISE_25519_AESGCM_BLAKE2B = CipherSuite(
            dhName = "25519", cipherName = "AESGCM", hashName = "BLAKE2b",
            dhlen = DHLEN, hashlen = 64, blocklen = 128,
            generateKeyPair = x25519Generate, dh = x25519DH, keyPairFromPrivate = x25519FromPrivate,
            encrypt = aesgcmEncrypt, decrypt = aesgcmDecrypt,
            hash = blake2bHash, hmacHash = blake2bHmacHash
        )
    }
}
