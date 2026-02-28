package dev.noiseprotocol.crypto

import dev.noiseprotocol.core.NoiseCipherFunction
import java.security.spec.AlgorithmParameterSpec
import javax.crypto.AEADBadTagException
import javax.crypto.BadPaddingException
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

abstract class JcaAeadCipherAdapter(
    private val transformation: String,
    private val keyAlgorithm: String
) : NoiseCipherFunction {
    override fun encrypt(
        key: ByteArray,
        nonce: ULong,
        associatedData: ByteArray,
        plaintext: ByteArray
    ): ByteArray {
        val cipher = initCipher(Cipher.ENCRYPT_MODE, key, nonce, associatedData)
        return cipher.doFinal(plaintext)
    }

    override fun decrypt(
        key: ByteArray,
        nonce: ULong,
        associatedData: ByteArray,
        ciphertext: ByteArray
    ): ByteArray {
        val cipher = initCipher(Cipher.DECRYPT_MODE, key, nonce, associatedData)
        return try {
            cipher.doFinal(ciphertext)
        } catch (error: AEADBadTagException) {
            throw IllegalArgumentException("Authentication failed.", error)
        } catch (error: BadPaddingException) {
            throw IllegalArgumentException("Authentication failed.", error)
        }
    }

    override fun rekey(key: ByteArray): ByteArray {
        val rekeyMaterial = encrypt(
            key = key,
            nonce = ULong.MAX_VALUE,
            associatedData = EMPTY,
            plaintext = ByteArray(KEY_SIZE_BYTES)
        )
        return rekeyMaterial.copyOf(KEY_SIZE_BYTES)
    }

    protected abstract fun nonceBytes(nonce: ULong): ByteArray

    protected abstract fun parameterSpec(nonce: ByteArray): AlgorithmParameterSpec

    private fun initCipher(mode: Int, key: ByteArray, nonce: ULong, associatedData: ByteArray): Cipher {
        require(key.size == KEY_SIZE_BYTES) { "Cipher key must be 32 bytes." }

        val cipher = Cipher.getInstance(transformation)
        val encodedNonce = nonceBytes(nonce)
        cipher.init(mode, SecretKeySpec(key.copyOf(), keyAlgorithm), parameterSpec(encodedNonce))
        if (associatedData.isNotEmpty()) {
            cipher.updateAAD(associatedData)
        }
        return cipher
    }

    private companion object {
        const val KEY_SIZE_BYTES = 32
        val EMPTY = ByteArray(0)
    }
}

class ChaCha20Poly1305CipherAdapter : JcaAeadCipherAdapter(
    transformation = "ChaCha20-Poly1305",
    keyAlgorithm = "ChaCha20"
) {
    override fun nonceBytes(nonce: ULong): ByteArray = NoiseNonceFormat.chacha20Poly1305(nonce)

    override fun parameterSpec(nonce: ByteArray): AlgorithmParameterSpec = IvParameterSpec(nonce)
}

class AesGcmCipherAdapter : JcaAeadCipherAdapter(
    transformation = "AES/GCM/NoPadding",
    keyAlgorithm = "AES"
) {
    override fun nonceBytes(nonce: ULong): ByteArray = NoiseNonceFormat.aesGcm(nonce)

    override fun parameterSpec(nonce: ByteArray): AlgorithmParameterSpec = GCMParameterSpec(128, nonce)
}

internal object NoiseNonceFormat {
    fun chacha20Poly1305(nonce: ULong): ByteArray = buildNoiseNonce(nonce, littleEndian = true)

    fun aesGcm(nonce: ULong): ByteArray = buildNoiseNonce(nonce, littleEndian = false)

    private fun buildNoiseNonce(nonce: ULong, littleEndian: Boolean): ByteArray {
        val nonceBytes = ByteArray(12)
        for (index in 0 until 8) {
            val shift = if (littleEndian) index else 7 - index
            nonceBytes[4 + index] = ((nonce shr (shift * 8)) and 0xFFu).toByte()
        }
        return nonceBytes
    }
}
