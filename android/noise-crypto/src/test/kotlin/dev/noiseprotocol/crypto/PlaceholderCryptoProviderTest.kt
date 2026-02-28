package noise.protocol.crypto

import noise.protocol.core.HandshakePattern
import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertFalse
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test

class CryptoProviderTest {
    private val key = ByteArray(32) { (it + 1).toByte() }
    private val associatedData = "noise-ad".encodeToByteArray()
    private val plaintext = "noise payload".encodeToByteArray()
    private val nonce = 7uL

    @Test
    fun supportsXxPattern() {
        val provider: NoiseProvider = CryptoProvider()
        assertTrue(provider.supports(HandshakePattern.XX))
    }

    @Test
    fun createDefaultConfigurationUsesNoiseXx25519AesGcmSha256() {
        val provider = CryptoProvider()
        val configuration = provider.createDefaultConfiguration()

        assertEquals("Noise_XX_25519_AESGCM_SHA256", configuration.protocolName)
        assertEquals(HandshakePattern.XX, configuration.pattern)
        assertTrue(configuration.suite.diffieHellman is X25519DiffieHellmanAdapter)
        assertTrue(configuration.suite.cipher is AesGcmCipherAdapter)
        assertTrue(configuration.suite.hash is Sha256HashAdapter)
        assertTrue(configuration.suite.keyDerivation is HkdfSha256Adapter)
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
    fun x448SharedSecretIsSymmetric() {
        val adapter = X448DiffieHellmanAdapter()
        val alice = adapter.generateKeyPair()
        val bob = adapter.generateKeyPair()

        val aliceShared = adapter.dh(alice.privateKey, bob.publicKey)
        val bobShared = adapter.dh(bob.privateKey, alice.publicKey)

        assertArrayEquals(aliceShared, bobShared)
        assertEquals(56, aliceShared.size)
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

    @Test
    fun supportsBlake2HashAndHkdf() {
        val input = "abc".encodeToByteArray()
        val expectedBlake2s =
            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982".hexToBytes()
        val expectedBlake2b =
            "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1" +
                "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
        assertArrayEquals(expectedBlake2s, Blake2sHashAdapter().hash(input))
        assertArrayEquals(expectedBlake2b.hexToBytes(), Blake2bHashAdapter().hash(input))

        val blake2sOutputs = HkdfBlake2sAdapter().hkdf(
            chainingKey = "ck".encodeToByteArray(),
            inputKeyMaterial = "ikm".encodeToByteArray(),
            outputs = 2
        )
        assertEquals(2, blake2sOutputs.size)
        blake2sOutputs.forEach { output -> assertEquals(32, output.size) }

        val blake2bOutputs = HkdfBlake2bAdapter().hkdf(
            chainingKey = "ck".encodeToByteArray(),
            inputKeyMaterial = "ikm".encodeToByteArray(),
            outputs = 2
        )
        assertEquals(2, blake2bOutputs.size)
        blake2bOutputs.forEach { output -> assertEquals(64, output.size) }
    }

    @Test
    fun providerCreatesSuiteForX448AndBlake2() {
        val provider = CryptoProvider()
        val suite = provider.createSuite(
            NoiseCryptoAlgorithms(
                dh = NoiseDhAlgorithm.X448,
                aead = NoiseAeadAlgorithm.CHACHA20_POLY1305,
                hash = NoiseHashAlgorithm.BLAKE2B
            )
        )
        val keyPair = suite.diffieHellman.generateKeyPair()
        assertEquals(56, keyPair.privateKey.size)
        assertEquals(56, keyPair.publicKey.size)
        assertEquals(64, suite.hash.hash("abc".encodeToByteArray()).size)
        val hkdf = suite.keyDerivation.hkdf("ck".encodeToByteArray(), "ikm".encodeToByteArray(), 2)
        assertEquals(2, hkdf.size)
        hkdf.forEach { output -> assertEquals(64, output.size) }
    }

    private fun String.hexToBytes(): ByteArray {
        val normalized = trim()
        require(normalized.length % 2 == 0) { "Hex string length must be even." }
        return ByteArray(normalized.length / 2) { index ->
            val byteIndex = index * 2
            normalized.substring(byteIndex, byteIndex + 2).toInt(16).toByte()
        }
    }
}
