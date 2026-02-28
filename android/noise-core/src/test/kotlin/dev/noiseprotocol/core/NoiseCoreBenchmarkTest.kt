package dev.noiseprotocol.core

import org.junit.jupiter.api.Assertions.assertArrayEquals
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Tag
import org.junit.jupiter.api.Test
import kotlin.math.max

@Tag("benchmark")
class NoiseCoreBenchmarkTest {
    private val fakeCryptoSuite = FakeNoiseCryptoSuite()

    @Test
    fun measuresHandshakeThroughputAcrossPatterns() {
        val patterns = listOf(
            HandshakePattern.NN,
            HandshakePattern.NK,
            HandshakePattern.KK,
            HandshakePattern.IK,
            HandshakePattern.XX
        )

        patterns.forEach { pattern ->
            runHandshakeRounds(pattern = pattern, rounds = 25)
        }

        val measuredRounds = 250
        patterns.forEach { pattern ->
            val startNs = System.nanoTime()
            val checksum = runHandshakeRounds(pattern = pattern, rounds = measuredRounds)
            val elapsedNs = System.nanoTime() - startNs
            val nsPerOp = elapsedNs / measuredRounds
            val opsPerSec = measuredRounds * 1_000_000_000.0 / elapsedNs.toDouble()

            assertTrue(elapsedNs > 0L)
            assertTrue(checksum > 0L)
            println(
                "benchmark noise-core handshake pattern=${pattern.name.lowercase()} rounds=$measuredRounds " +
                    "elapsed_ns=$elapsedNs ns_per_op=$nsPerOp ops_per_s=$opsPerSec checksum=$checksum"
            )
        }
    }

    @Test
    fun measuresTransportEncryptDecryptThroughput() {
        runTransportLoops(iterations = 500)

        val measuredIterations = 15_000
        val startNs = System.nanoTime()
        val result = runTransportLoops(iterations = measuredIterations)
        val elapsedNs = System.nanoTime() - startNs
        val nsPerOp = elapsedNs / measuredIterations
        val opsPerSec = measuredIterations * 1_000_000_000.0 / elapsedNs.toDouble()

        assertTrue(elapsedNs > 0L)
        assertEquals(measuredIterations.toULong(), result.txNonce)
        assertEquals(measuredIterations.toULong(), result.rxNonce)
        assertEquals((measuredIterations * (result.payloadSize + 1)).toLong(), result.totalCiphertextBytes)
        assertTrue(result.checksum > 0L)
        println(
            "benchmark noise-core transport encrypt_decrypt iterations=$measuredIterations " +
                "elapsed_ns=$elapsedNs ns_per_op=$nsPerOp ops_per_s=$opsPerSec " +
                "bytes=${result.totalCiphertextBytes} checksum=${result.checksum}"
        )
    }

    private fun runHandshakeRounds(pattern: HandshakePattern, rounds: Int): Long {
        var checksum = 0L
        repeat(rounds) { round ->
            val baseSeed = pattern.ordinal * 1_000 + round * 10
            val initiatorStatic = keyPair(baseSeed + 1)
            val responderStatic = keyPair(baseSeed + 2)
            var initiatorEphemeralSeed = baseSeed + 100
            var responderEphemeralSeed = baseSeed + 200

            val initiator = HandshakeState.initialize(
                pattern = pattern,
                role = HandshakeRole.INITIATOR,
                cryptoSuite = fakeCryptoSuite,
                localStatic = initiatorStatic,
                remoteStatic = responderStatic.publicKey,
                ephemeralKeyGenerator = { keyPair(initiatorEphemeralSeed++) }
            )
            val responder = HandshakeState.initialize(
                pattern = pattern,
                role = HandshakeRole.RESPONDER,
                cryptoSuite = fakeCryptoSuite,
                localStatic = responderStatic,
                remoteStatic = initiatorStatic.publicKey,
                ephemeralKeyGenerator = { keyPair(responderEphemeralSeed++) }
            )

            pattern.messages.forEachIndexed { messageIndex, messagePattern ->
                val payload = byteArrayOf(
                    pattern.ordinal.toByte(),
                    (round and 0xFF).toByte(),
                    messageIndex.toByte()
                )
                val (sender, receiver) = if (messagePattern.direction == MessageDirection.INITIATOR_TO_RESPONDER) {
                    initiator to responder
                } else {
                    responder to initiator
                }
                val message = sender.writeMessage(payload)
                assertArrayEquals(payload, receiver.readMessage(message))
            }

            assertTrue(initiator.isComplete())
            assertTrue(responder.isComplete())
            val initiatorHash = initiator.handshakeHash()
            val responderHash = responder.handshakeHash()
            assertArrayEquals(initiatorHash, responderHash)
            checksum +=
                (initiatorHash[0].toInt() and 0xFF) +
                (initiatorHash[1].toInt() and 0xFF) +
                pattern.messages.size
        }
        return checksum
    }

    private fun runTransportLoops(iterations: Int): TransportLoopResult {
        val txState = CipherState(fakeCryptoSuite.cipher, initialKey = byteArrayOf(3, 1, 4, 1, 5))
        val rxState = CipherState(fakeCryptoSuite.cipher, initialKey = byteArrayOf(3, 1, 4, 1, 5))
        val associatedData = byteArrayOf(9, 2, 6, 5)
        val payloadSize = 32
        var totalCiphertextBytes = 0L
        var checksum = 0L

        repeat(iterations) { iteration ->
            val plaintext = ByteArray(payloadSize) { index ->
                ((iteration + index) and 0xFF).toByte()
            }
            val ciphertext = txState.encryptWithAd(associatedData = associatedData, plaintext = plaintext)
            val decrypted = rxState.decryptWithAd(associatedData = associatedData, ciphertext = ciphertext)
            assertArrayEquals(plaintext, decrypted)

            totalCiphertextBytes += ciphertext.size.toLong()
            checksum += (decrypted.first().toInt() and 0xFF).toLong()
        }

        return TransportLoopResult(
            txNonce = txState.nonce,
            rxNonce = rxState.nonce,
            payloadSize = payloadSize,
            totalCiphertextBytes = totalCiphertextBytes,
            checksum = checksum
        )
    }

    private data class TransportLoopResult(
        val txNonce: ULong,
        val rxNonce: ULong,
        val payloadSize: Int,
        val totalCiphertextBytes: Long,
        val checksum: Long
    )

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
        private var nextSeed: Int = 10_000

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
