package dev.noiseprotocol.crypto

import dev.noiseprotocol.core.HandshakePattern
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class JcaCryptoProviderTest {
    private val key = ByteArray(32) { (it + 1).toByte() }
    private val associatedData = "noise-ad".encodeToByteArray()
    private val plaintext = "noise payload".encodeToByteArray()
    private val nonce = 7uL

    @Test
    fun supportsXxPattern() {
        val provider: CryptoProvider = JcaCryptoProvider()
        assertTrue(provider.supports(HandshakePattern.XX))
    }

    @Test
    fun encryptDecryptRoundTripForChaCha20Poly1305() {
        val cipher = ChaCha20Poly1305CipherAdapter()
        val ciphertext = cipher.encrypt(key, nonce, associatedData, plaintext)

        val decrypted = cipher.decrypt(key, nonce, associatedData, ciphertext)
        assertArrayEquals(plaintext, decrypted)
    }

    @Test
    fun encryptDecryptRoundTripForAesGcm() {
        val cipher = AesGcmCipherAdapter()
        val ciphertext = cipher.encrypt(key, nonce, associatedData, plaintext)

        val decrypted = cipher.decrypt(key, nonce, associatedData, ciphertext)
        assertArrayEquals(plaintext, decrypted)
    }

    @Test
    fun decryptFailsOnTamperingForChaCha20Poly1305() {
        val cipher = ChaCha20Poly1305CipherAdapter()
        val ciphertext = cipher.encrypt(key, nonce, associatedData, plaintext)
        val tampered = ciphertext.copyOf().also { value ->
            value[value.lastIndex] = (value.last().toInt() xor 0x01).toByte()
        }

        assertThrows(IllegalArgumentException::class.java) {
            cipher.decrypt(key, nonce, associatedData, tampered)
        }
    }

    @Test
    fun decryptFailsOnTamperingForAesGcm() {
        val cipher = AesGcmCipherAdapter()
        val ciphertext = cipher.encrypt(key, nonce, associatedData, plaintext)
        val tampered = ciphertext.copyOf().also { value ->
            value[value.lastIndex] = (value.last().toInt() xor 0x01).toByte()
        }

        assertThrows(IllegalArgumentException::class.java) {
            cipher.decrypt(key, nonce, associatedData, tampered)
        }
    }

    @Test
    fun hkdfReturnsRequestedCountWithExpectedLengths() {
        val sha256Outputs = HkdfSha256Adapter().hkdf(
            chainingKey = "ck".encodeToByteArray(),
            inputKeyMaterial = "ikm".encodeToByteArray(),
            outputs = 3
        )
        assertEquals(3, sha256Outputs.size)
        sha256Outputs.forEach { output -> assertEquals(32, output.size) }

        val sha512Outputs = HkdfSha512Adapter().hkdf(
            chainingKey = "ck".encodeToByteArray(),
            inputKeyMaterial = "ikm".encodeToByteArray(),
            outputs = 2
        )
        assertEquals(2, sha512Outputs.size)
        sha512Outputs.forEach { output -> assertEquals(64, output.size) }
    }

    @Test
    fun x25519SharedSecretIsSymmetric() {
        val adapter = X25519DiffieHellmanAdapter()
        val alice = adapter.generateKeyPair()
        val bob = adapter.generateKeyPair()

        val aliceShared = adapter.dh(alice.privateKey, bob.publicKey)
        val bobShared = adapter.dh(bob.privateKey, alice.publicKey)

        assertArrayEquals(aliceShared, bobShared)
        assertEquals(32, aliceShared.size)
    }

    @Test
    fun nonceFormattingAndRekeyMatchNoiseContracts() {
        val counter = 0x0102030405060708uL
        assertArrayEquals(
            byteArrayOf(
                0, 0, 0, 0,
                8, 7, 6, 5, 4, 3, 2, 1
            ),
            NoiseNonceFormat.chacha20Poly1305(counter)
        )
        assertArrayEquals(
            byteArrayOf(
                0, 0, 0, 0,
                1, 2, 3, 4, 5, 6, 7, 8
            ),
            NoiseNonceFormat.aesGcm(counter)
        )

        val chachaRekey = ChaCha20Poly1305CipherAdapter().rekey(key)
        val aesRekey = AesGcmCipherAdapter().rekey(key)
        assertEquals(32, chachaRekey.size)
        assertEquals(32, aesRekey.size)
        assertFalse(chachaRekey.contentEquals(key))
        assertFalse(aesRekey.contentEquals(key))
    }
}
