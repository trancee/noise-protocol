package noise.protocol.core

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertThrows
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import kotlin.math.max

class NoiseCoreStubTest {
    private val fakeCryptoSuite = FakeNoiseCryptoSuite()

    @Test
    fun supportsNoisePatternsWithExpectedTokenTables() {
        assertEquals(
            setOf(
                HandshakePattern.NN,
                HandshakePattern.NK,
                HandshakePattern.KK,
                HandshakePattern.IK,
                HandshakePattern.XX
            ),
            NoiseCoreStub.supportedPatterns()
        )

        assertEquals(
            emptyList<PreMessagePattern>(),
            HandshakePattern.NN.preMessages
        )
        assertEquals(
            listOf(
                MessagePattern(MessageDirection.INITIATOR_TO_RESPONDER, listOf(HandshakeToken.E)),
                MessagePattern(MessageDirection.RESPONDER_TO_INITIATOR, listOf(HandshakeToken.E, HandshakeToken.EE))
            ),
            HandshakePattern.NN.messages
        )

        assertEquals(
            listOf(
                PreMessagePattern(MessageDirection.RESPONDER_TO_INITIATOR, listOf(HandshakeToken.S))
            ),
            HandshakePattern.NK.preMessages
        )
        assertEquals(
            listOf(
                MessagePattern(MessageDirection.INITIATOR_TO_RESPONDER, listOf(HandshakeToken.E, HandshakeToken.ES)),
                MessagePattern(MessageDirection.RESPONDER_TO_INITIATOR, listOf(HandshakeToken.E, HandshakeToken.EE))
            ),
            HandshakePattern.NK.messages
        )

        assertEquals(
            listOf(
                PreMessagePattern(MessageDirection.INITIATOR_TO_RESPONDER, listOf(HandshakeToken.S)),
                PreMessagePattern(MessageDirection.RESPONDER_TO_INITIATOR, listOf(HandshakeToken.S))
            ),
            HandshakePattern.KK.preMessages
        )
        assertEquals(
            listOf(
                MessagePattern(
                    MessageDirection.INITIATOR_TO_RESPONDER,
                    listOf(HandshakeToken.E, HandshakeToken.ES, HandshakeToken.SS)
                ),
                MessagePattern(
                    MessageDirection.RESPONDER_TO_INITIATOR,
                    listOf(HandshakeToken.E, HandshakeToken.EE, HandshakeToken.SE)
                )
            ),
            HandshakePattern.KK.messages
        )

        assertEquals(
            listOf(
                PreMessagePattern(MessageDirection.RESPONDER_TO_INITIATOR, listOf(HandshakeToken.S))
            ),
            HandshakePattern.IK.preMessages
        )
        assertEquals(
            listOf(
                MessagePattern(
                    MessageDirection.INITIATOR_TO_RESPONDER,
                    listOf(HandshakeToken.E, HandshakeToken.ES, HandshakeToken.S, HandshakeToken.SS)
                ),
                MessagePattern(
                    MessageDirection.RESPONDER_TO_INITIATOR,
                    listOf(HandshakeToken.E, HandshakeToken.EE, HandshakeToken.SE)
                )
            ),
            HandshakePattern.IK.messages
        )

        assertEquals(
            emptyList<PreMessagePattern>(),
            HandshakePattern.XX.preMessages
        )
        assertEquals(
            listOf(
                MessagePattern(MessageDirection.INITIATOR_TO_RESPONDER, listOf(HandshakeToken.E)),
                MessagePattern(
                    MessageDirection.RESPONDER_TO_INITIATOR,
                    listOf(HandshakeToken.E, HandshakeToken.EE, HandshakeToken.S, HandshakeToken.ES)
                ),
                MessagePattern(MessageDirection.INITIATOR_TO_RESPONDER, listOf(HandshakeToken.S, HandshakeToken.SE))
            ),
            HandshakePattern.XX.messages
        )
    }

    @Test
    fun enforcesHandshakeDirectionAndOrder() {
        val initiator = HandshakeState.initialize(
            pattern = HandshakePattern.NN,
            role = HandshakeRole.INITIATOR,
            cryptoSuite = fakeCryptoSuite,
            ephemeralKeyGenerator = { keyPair(1) }
        )
        val responder = HandshakeState.initialize(
            pattern = HandshakePattern.NN,
            role = HandshakeRole.RESPONDER,
            cryptoSuite = fakeCryptoSuite,
            ephemeralKeyGenerator = { keyPair(2) }
        )

        val first = initiator.writeMessage("m1".encodeToByteArray())
        assertThrows(IllegalStateException::class.java) {
            initiator.writeMessage("wrong-turn".encodeToByteArray())
        }

        assertArrayEquals("m1".encodeToByteArray(), responder.readMessage(first))

        val second = responder.writeMessage("m2".encodeToByteArray())
        assertArrayEquals("m2".encodeToByteArray(), initiator.readMessage(second))
        assertTrue(initiator.isComplete())
        assertTrue(responder.isComplete())

        val xxInitiator = HandshakeState.initialize(
            pattern = HandshakePattern.XX,
            role = HandshakeRole.INITIATOR,
            cryptoSuite = fakeCryptoSuite,
            localStatic = keyPair(10),
            ephemeralKeyGenerator = { keyPair(11) }
        )
        val xxResponder = HandshakeState.initialize(
            pattern = HandshakePattern.XX,
            role = HandshakeRole.RESPONDER,
            cryptoSuite = fakeCryptoSuite,
            localStatic = keyPair(20),
            ephemeralKeyGenerator = { keyPair(21) }
        )

        val xxMessage1 = xxInitiator.writeMessage("one".encodeToByteArray())
        xxResponder.readMessage(xxMessage1)
        val xxMessage2 = xxResponder.writeMessage("two".encodeToByteArray())

        assertThrows(IllegalArgumentException::class.java) {
            xxInitiator.readMessage(xxMessage2.copy(direction = MessageDirection.INITIATOR_TO_RESPONDER))
        }

        assertThrows(IllegalArgumentException::class.java) {
            xxInitiator.readMessage(xxMessage2.copy(tokenValues = xxMessage2.tokenValues.reversed()))
        }
    }

    @Test
    fun cipherStateTracksNonceAndGuardsOverflow() {
        val cipherState = CipherState(fakeCryptoSuite.cipher, initialKey = byteArrayOf(7, 9, 11))

        assertEquals(0uL, cipherState.nonce)
        cipherState.encryptWithAd(byteArrayOf(1, 2), byteArrayOf(3, 4))
        assertEquals(1uL, cipherState.nonce)

        cipherState.initializeKey(null)
        val passthrough = byteArrayOf(5, 6, 7)
        assertArrayEquals(passthrough, cipherState.encryptWithAd(byteArrayOf(9), passthrough))
        assertEquals(0uL, cipherState.nonce)

        cipherState.initializeKey(byteArrayOf(42))
        cipherState.setNonce(ULong.MAX_VALUE - 1uL)
        cipherState.encryptWithAd(byteArrayOf(), byteArrayOf(1))
        assertEquals(ULong.MAX_VALUE, cipherState.nonce)

        assertThrows(IllegalStateException::class.java) {
            cipherState.encryptWithAd(byteArrayOf(), byteArrayOf(2))
        }
    }

    @Test
    fun symmetricStateIsDeterministicWithFakeCrypto() {
        val sender = SymmetricState(
            hashFunction = fakeCryptoSuite.hash,
            keyDerivationFunction = fakeCryptoSuite.keyDerivation,
            cipherFunction = fakeCryptoSuite.cipher,
            protocolName = HandshakePattern.XX.protocolName
        )
        val receiver = SymmetricState(
            hashFunction = fakeCryptoSuite.hash,
            keyDerivationFunction = fakeCryptoSuite.keyDerivation,
            cipherFunction = fakeCryptoSuite.cipher,
            protocolName = HandshakePattern.XX.protocolName
        )

        sender.mixHash("prologue".encodeToByteArray())
        receiver.mixHash("prologue".encodeToByteArray())
        sender.mixKey(byteArrayOf(1, 2, 3, 4))
        receiver.mixKey(byteArrayOf(1, 2, 3, 4))

        val ciphertext = sender.encryptAndHash("payload".encodeToByteArray())
        val plaintext = receiver.decryptAndHash(ciphertext)

        assertArrayEquals("payload".encodeToByteArray(), plaintext)
        assertArrayEquals(sender.handshakeHash, receiver.handshakeHash)
        assertArrayEquals(sender.chainingKey, receiver.chainingKey)

        val (senderTx, senderRx) = sender.split()
        val (receiverTx, receiverRx) = receiver.split()

        assertArrayEquals(requireNotNull(senderTx.keyMaterial()), requireNotNull(receiverTx.keyMaterial()))
        assertArrayEquals(requireNotNull(senderRx.keyMaterial()), requireNotNull(receiverRx.keyMaterial()))
    }

    private class FakeNoiseCryptoSuite : NoiseCryptoSuite {
        override val hash: NoiseHashFunction = FakeHashFunction()
        override val keyDerivation: NoiseKeyDerivationFunction = FakeKeyDerivationFunction(hash)
        override val cipher: NoiseCipherFunction = FakeCipherFunction()
        override val diffieHellman: NoiseDiffieHellmanFunction = FakeDiffieHellmanFunction()
    }

    private class FakeHashFunction : NoiseHashFunction {
        override val hashLength: Int = 32

        override fun hash(data: ByteArray): ByteArray {
            val output = ByteArray(hashLength)
            var accumulator = 17
            data.forEachIndexed { index, byte ->
                accumulator = (accumulator * 31 + (byte.toInt() and 0xFF) + index) and 0xFF
                val slot = index % hashLength
                output[slot] = (output[slot].toInt() xor accumulator).toByte()
            }
            return output
        }
    }

    private class FakeKeyDerivationFunction(
        private val hashFunction: NoiseHashFunction
    ) : NoiseKeyDerivationFunction {
        override fun hkdf(chainingKey: ByteArray, inputKeyMaterial: ByteArray, outputs: Int): List<ByteArray> {
            require(outputs > 0) { "HKDF output count must be positive." }
            val seed = chainingKey + inputKeyMaterial
            return (1..outputs).map { index ->
                hashFunction.hash(seed + byteArrayOf(index.toByte()))
            }
        }
    }

    private class FakeCipherFunction : NoiseCipherFunction {
        override fun encrypt(
            key: ByteArray,
            nonce: ULong,
            associatedData: ByteArray,
            plaintext: ByteArray
        ): ByteArray {
            val mask = computeMask(key, nonce, associatedData)
            val transformed = plaintext.map { byte ->
                (byte.toInt() xor mask).toByte()
            }.toByteArray()
            return transformed + mask.toByte()
        }

        override fun decrypt(
            key: ByteArray,
            nonce: ULong,
            associatedData: ByteArray,
            ciphertext: ByteArray
        ): ByteArray {
            require(ciphertext.isNotEmpty()) { "Ciphertext must include fake authentication tag." }
            val expectedMask = computeMask(key, nonce, associatedData).toByte()
            val providedMask = ciphertext.last()
            require(expectedMask == providedMask) { "Fake authentication failed." }

            return ciphertext.copyOf(ciphertext.size - 1).map { byte ->
                (byte.toInt() xor (providedMask.toInt() and 0xFF)).toByte()
            }.toByteArray()
        }

        override fun rekey(key: ByteArray): ByteArray {
            return key.map { byte ->
                (byte.toInt() xor 0x5A).toByte()
            }.toByteArray()
        }

        private fun computeMask(key: ByteArray, nonce: ULong, associatedData: ByteArray): Int {
            var mask = (nonce and 0xFFu).toInt()
            key.forEach { byte -> mask = (mask + (byte.toInt() and 0xFF)) and 0xFF }
            associatedData.forEach { byte -> mask = (mask xor (byte.toInt() and 0xFF)) and 0xFF }
            return mask
        }
    }

    private class FakeDiffieHellmanFunction : NoiseDiffieHellmanFunction {
        private var nextSeed: Int = 100

        override fun generateKeyPair(): NoiseKeyPair {
            return keyPair(nextSeed++)
        }

        override fun dh(localPrivateKey: ByteArray, remotePublicKey: ByteArray): ByteArray {
            val outputLength = max(localPrivateKey.size, remotePublicKey.size)
            return ByteArray(outputLength) { index ->
                val local = localPrivateKey[index % localPrivateKey.size]
                val remote = remotePublicKey[index % remotePublicKey.size]
                (local.toInt() xor remote.toInt()).toByte()
            }
        }
    }

    private companion object {
        fun keyPair(seed: Int): NoiseKeyPair {
            val privateKey = byteArrayOf(
                seed.toByte(),
                (seed + 1).toByte(),
                (seed + 2).toByte(),
                (seed + 3).toByte()
            )
            val publicKey = privateKey.copyOf()
            return NoiseKeyPair(privateKey = privateKey, publicKey = publicKey)
        }
    }
}
